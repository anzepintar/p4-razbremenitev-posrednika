#include "quic_sni.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <algorithm>
#include <cstring>

namespace quic {
namespace {

const uint8_t kInitialSalt[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
};

const uint32_t kVersion1 = 0x00000001;
const size_t kSampleLen = 16;
const size_t kTagLen = 16;
const size_t kMaxCid = 20;
const uint8_t kClientHello = 0x01;
// Toliko zacetnih bajtov ClientHello se hrani kot odtis toka; zajame odjemalcevo
// nakljucje (32 bajtov od odmika 6), zato je za vsako povezavo drugacen.
const size_t kFingerprint = 40;
const uint16_t kExtServerName = 0;
const size_t kMaxSpans = 64;

struct Reader {
    const uint8_t *data;
    size_t len;
    size_t at = 0;

    bool left(size_t need) const { return need <= len && at <= len - need; }

    bool byte(uint8_t *out) {
        if (!left(1)) return false;
        *out = data[at++];
        return true;
    }

    bool skip(size_t count) {
        if (!left(count)) return false;
        at += count;
        return true;
    }

    bool varint(uint64_t *out) {
        if (!left(1)) return false;
        size_t width = (size_t)1 << (data[at] >> 6);
        if (!left(width)) return false;
        uint64_t value = data[at] & 0x3f;
        for (size_t i = 1; i < width; i++) value = (value << 8) | data[at + i];
        at += width;
        *out = value;
        return true;
    }
};

uint16_t be16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
uint32_t be24(const uint8_t *p) { return (uint32_t)((p[0] << 16) | (p[1] << 8) | p[2]); }
uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

bool hkdf(int mode, const uint8_t *salt, size_t salt_len,
          const uint8_t *key, size_t key_len,
          const uint8_t *info, size_t info_len,
          uint8_t *out, size_t out_len) {
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (kdf == nullptr) return false;
    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (ctx == nullptr) return false;

    char digest[] = "SHA256";
    OSSL_PARAM params[6];
    int count = 0;
    params[count++] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
    params[count++] = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    params[count++] = OSSL_PARAM_construct_octet_string(
        OSSL_KDF_PARAM_KEY, (void *)key, key_len);
    if (salt != nullptr)
        params[count++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, (void *)salt, salt_len);
    if (info != nullptr)
        params[count++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, (void *)info, info_len);
    params[count] = OSSL_PARAM_construct_end();

    bool ok = EVP_KDF_derive(ctx, out, out_len, params) > 0;
    EVP_KDF_CTX_free(ctx);
    return ok;
}

bool expand_label(const uint8_t *secret, const char *label,
                  uint8_t *out, size_t out_len) {
    std::string full = std::string("tls13 ") + label;
    std::vector<uint8_t> info;
    info.push_back((uint8_t)(out_len >> 8));
    info.push_back((uint8_t)(out_len & 0xff));
    info.push_back((uint8_t)full.size());
    info.insert(info.end(), full.begin(), full.end());
    info.push_back(0);
    return hkdf(EVP_KDF_HKDF_MODE_EXPAND_ONLY, nullptr, 0, secret, 32,
                info.data(), info.size(), out, out_len);
}

struct Keys {
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t hp[16];
};

bool client_keys(const uint8_t *cid, size_t cid_len, Keys *keys) {
    uint8_t initial[32];
    uint8_t client[32];
    if (!hkdf(EVP_KDF_HKDF_MODE_EXTRACT_ONLY, kInitialSalt, sizeof(kInitialSalt),
              cid, cid_len, nullptr, 0, initial, sizeof(initial)))
        return false;
    if (!expand_label(initial, "client in", client, sizeof(client))) return false;
    return expand_label(client, "quic key", keys->key, sizeof(keys->key))
        && expand_label(client, "quic iv", keys->iv, sizeof(keys->iv))
        && expand_label(client, "quic hp", keys->hp, sizeof(keys->hp));
}

bool header_mask(const uint8_t *hp, const uint8_t *sample, uint8_t *mask) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;
    int len = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, hp, nullptr) == 1
        && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1
        && EVP_EncryptUpdate(ctx, mask, &len, sample, (int)kSampleLen) == 1
        && len == (int)kSampleLen;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool aead_open(const Keys &keys, uint64_t number,
               const uint8_t *aad, size_t aad_len,
               const uint8_t *body, size_t body_len,
               std::vector<uint8_t> *out) {
    if (body_len <= kTagLen) return false;

    uint8_t nonce[12];
    std::memcpy(nonce, keys.iv, sizeof(nonce));
    for (size_t i = 0; i < 8; i++)
        nonce[sizeof(nonce) - 1 - i] ^= (uint8_t)(number >> (8 * i));

    size_t text_len = body_len - kTagLen;
    out->resize(text_len);

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) return false;
    int len = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)sizeof(nonce), nullptr) == 1
        && EVP_DecryptInit_ex(ctx, nullptr, nullptr, keys.key, nonce) == 1
        && EVP_DecryptUpdate(ctx, nullptr, &len, aad, (int)aad_len) == 1
        && EVP_DecryptUpdate(ctx, out->data(), &len, body, (int)text_len) == 1
        && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, (int)kTagLen,
                               (void *)(body + text_len)) == 1
        && EVP_DecryptFinal_ex(ctx, out->data() + len, &len) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

struct Initial {
    size_t number_offset = 0;
    size_t body_len = 0;
    size_t total = 0;
    const uint8_t *cid = nullptr;
    size_t cid_len = 0;
    const uint8_t *scid = nullptr;
    size_t scid_len = 0;
    bool is_initial = false;
};

bool parse_long_header(const uint8_t *data, size_t len, Initial *out) {
    Reader reader{data, len};
    uint8_t first = 0;
    if (!reader.byte(&first)) return false;
    if ((first & 0xc0) != 0xc0) return false;
    if (!reader.left(4) || be32(data + reader.at) != kVersion1) return false;
    reader.at += 4;

    uint8_t cid_len = 0;
    if (!reader.byte(&cid_len) || cid_len > kMaxCid || !reader.left(cid_len)) return false;
    out->cid = data + reader.at;
    out->cid_len = cid_len;
    reader.at += cid_len;

    uint8_t scid_len = 0;
    if (!reader.byte(&scid_len) || scid_len > kMaxCid || !reader.left(scid_len)) return false;
    out->scid = data + reader.at;
    out->scid_len = scid_len;
    reader.at += scid_len;

    out->is_initial = (first & 0x30) == 0x00;
    if (out->is_initial) {
        uint64_t token_len = 0;
        if (!reader.varint(&token_len) || !reader.skip((size_t)token_len)) return false;
    }

    uint64_t body_len = 0;
    if (!reader.varint(&body_len) || !reader.left((size_t)body_len)) return false;
    out->number_offset = reader.at;
    out->body_len = (size_t)body_len;
    out->total = reader.at + (size_t)body_len;
    return true;
}

bool open_initial(const uint8_t *data, size_t len, const Initial &packet,
                  std::vector<uint8_t> *payload) {
    if (packet.number_offset + 4 + kSampleLen > packet.total || packet.total > len)
        return false;

    Keys keys;
    if (!client_keys(packet.cid, packet.cid_len, &keys)) return false;

    uint8_t mask[kSampleLen];
    if (!header_mask(keys.hp, data + packet.number_offset + 4, mask)) return false;

    uint8_t first = data[0] ^ (mask[0] & 0x0f);
    size_t number_len = (size_t)(first & 0x03) + 1;
    if (packet.body_len <= number_len + kTagLen) return false;

    std::vector<uint8_t> header(data, data + packet.number_offset + number_len);
    header[0] = first;
    uint64_t number = 0;
    for (size_t i = 0; i < number_len; i++) {
        header[packet.number_offset + i] ^= mask[1 + i];
        number = (number << 8) | header[packet.number_offset + i];
    }

    return aead_open(keys, number, header.data(), header.size(),
                     data + packet.number_offset + number_len,
                     packet.body_len - number_len, payload);
}

bool collect_crypto(const std::vector<uint8_t> &payload, std::vector<Chunk> *chunks) {
    Reader reader{payload.data(), payload.size()};
    while (reader.at < reader.len) {
        uint64_t type = 0;
        if (!reader.varint(&type)) return false;
        if (type == 0x00 || type == 0x01) continue;
        if (type == 0x02 || type == 0x03) {
            uint64_t largest = 0, delay = 0, count = 0, first = 0;
            if (!reader.varint(&largest) || !reader.varint(&delay)
                || !reader.varint(&count) || !reader.varint(&first)) return false;
            for (uint64_t i = 0; i < count; i++) {
                uint64_t gap = 0, block = 0;
                if (!reader.varint(&gap) || !reader.varint(&block)) return false;
            }
            if (type == 0x03) {
                uint64_t ect0 = 0, ect1 = 0, ce = 0;
                if (!reader.varint(&ect0) || !reader.varint(&ect1)
                    || !reader.varint(&ce)) return false;
            }
            continue;
        }
        if (type == 0x06) {
            uint64_t offset = 0, size = 0;
            if (!reader.varint(&offset) || !reader.varint(&size)) return false;
            if (!reader.left((size_t)size)) return false;
            chunks->push_back(Chunk{offset, reader.data + reader.at, (size_t)size});
            reader.at += (size_t)size;
            continue;
        }
        return false;
    }
    return true;
}

enum class Sni { FOUND, ABSENT, MORE };

Sni sni_from_client_hello(const uint8_t *data, size_t len,
                          uint32_t max_name, std::string *sni) {
    Reader reader{data, len};
    if (!reader.skip(2 + 32)) return Sni::MORE;

    uint8_t session_len = 0;
    if (!reader.byte(&session_len) || !reader.skip(session_len)) return Sni::MORE;
    if (!reader.left(2)) return Sni::MORE;
    uint16_t cipher_len = be16(data + reader.at);
    if (!reader.skip(2u + cipher_len)) return Sni::MORE;

    uint8_t compression_len = 0;
    if (!reader.byte(&compression_len) || !reader.skip(compression_len)) return Sni::MORE;
    if (!reader.left(2)) return Sni::MORE;
    size_t end = reader.at + 2 + be16(data + reader.at);
    reader.at += 2;

    while (reader.at + 4 <= std::min(end, len)) {
        uint16_t etype = be16(data + reader.at);
        uint16_t elen = be16(data + reader.at + 2);
        reader.at += 4;
        if (reader.at + elen > end) return Sni::ABSENT;
        if (etype != kExtServerName) {
            reader.at += elen;
            continue;
        }
        if (reader.at + elen > len) return Sni::MORE;

        size_t at = reader.at;
        size_t stop = reader.at + elen;
        if (at + 2 > stop) return Sni::ABSENT;
        at += 2;
        while (at + 3 <= stop) {
            uint8_t type = data[at];
            uint16_t name_len = be16(data + at + 1);
            at += 3;
            if (at + name_len > stop) return Sni::ABSENT;
            if (type == 0) {
                if (name_len == 0 || name_len > max_name) return Sni::ABSENT;
                sni->assign((const char *)(data + at), name_len);
                return Sni::FOUND;
            }
            at += name_len;
        }
        return Sni::ABSENT;
    }
    return reader.at >= end ? Sni::ABSENT : Sni::MORE;
}

}  // namespace

void Tracker::configure(const Config &config) { config_ = config; }

Tracker::Flow &Tracker::touch(const Key &key, uint64_t now_ms) {
    auto found = table_.find(key);
    if (found != table_.end()) {
        found->second.seen_ms = now_ms;
        return found->second;
    }
    if (++since_sweep_ >= 1024 || table_.size() >= config_.max_flows) sweep(now_ms);
    Flow &flow = table_[key];
    flow.seen_ms = now_ms;
    return flow;
}

void Tracker::sweep(uint64_t now_ms) {
    since_sweep_ = 0;
    for (auto it = table_.begin(); it != table_.end();) {
        if (now_ms - it->second.seen_ms > config_.flow_timeout_ms)
            it = table_.erase(it);
        else
            ++it;
    }
    if (table_.size() < config_.max_flows) return;

    std::vector<uint64_t> stamps;
    stamps.reserve(table_.size());
    for (const auto &entry : table_) stamps.push_back(entry.second.seen_ms);
    size_t half = stamps.size() / 2;
    std::nth_element(stamps.begin(), stamps.begin() + half, stamps.end());
    uint64_t cutoff = stamps[half];
    for (auto it = table_.begin(); it != table_.end();) {
        if (it->second.seen_ms <= cutoff)
            it = table_.erase(it);
        else
            ++it;
    }
}

bool Tracker::collect(const uint8_t *data, size_t len, std::vector<Chunk> *chunks,
                     std::vector<std::vector<uint8_t>> *payloads, bool *bad) {
    *bad = false;
    size_t at = 0;
    while (at < len) {
        Initial packet;
        if (!parse_long_header(data + at, len - at, &packet)) break;
        if (packet.is_initial) {
            payloads->emplace_back();
            if (!open_initial(data + at, len - at, packet, &payloads->back())) {
                payloads->pop_back();
            } else if (!collect_crypto(payloads->back(), chunks)) {
                *bad = true;
                return false;
            }
        }
        at += packet.total;
    }
    return !chunks->empty();
}

bool Tracker::absorb(Flow &flow, const std::vector<Chunk> &chunks) {
    if (flow.spans.size() + chunks.size() > kMaxSpans) {
        flow.failed = true;
        return false;
    }

    for (const Chunk &chunk : chunks) {
        uint64_t end = chunk.offset + chunk.len;
        if (end > config_.max_crypto) {
            flow.failed = true;
            return false;
        }
        if (flow.crypto.size() < end) flow.crypto.resize((size_t)end, 0);
        std::memcpy(flow.crypto.data() + chunk.offset, chunk.data, chunk.len);
        flow.spans.push_back({(uint32_t)chunk.offset, (uint32_t)end});
    }

    std::sort(flow.spans.begin(), flow.spans.end());
    uint32_t have = 0;
    for (const auto &span : flow.spans) {
        if (span.first > have) break;
        have = std::max(have, span.second);
    }
    if (have < 4) return false;

    const uint8_t *message = flow.crypto.data();
    if (message[0] != kClientHello) {
        flow.failed = true;
        return false;
    }
    size_t size = be24(message + 1);
    size_t body = std::min(size, (size_t)have - 4);
    Sni state = sni_from_client_hello(message + 4, body, config_.max_name, &flow.sni);
    if (state != Sni::FOUND) {
        flow.sni.clear();
        if (body < size) return false;
    }

    flow.resolved = true;
    flow.crypto.clear();
    flow.crypto.shrink_to_fit();
    flow.spans.clear();
    return true;
}

Result Tracker::classify(const Key &key, const uint8_t *data, size_t len, uint64_t now_ms) {
    std::vector<Chunk> chunks;
    std::vector<std::vector<uint8_t>> payloads;
    bool bad = false;
    bool got = data != nullptr && len > 0 && collect(data, len, &chunks, &payloads, &bad);

    // CRYPTO z odmikom 0 v desifriranem Initialu je zacetek ClientHello. Odtis prvih
    // kFingerprint bajtov zajame nakljucje odjemalca, zato loci ponovljen datagram (enak
    // odtis) od nove povezave na ponovno uporabljenem cetvorcku (drugacen odtis). Odjemalcev
    // Initial sredi rokovanja ima DCID streznika in se s temi kljuci sploh ne odpre.
    std::vector<uint8_t> hello;
    for (const Chunk &chunk : chunks) {
        if (chunk.offset != 0) continue;
        size_t take = std::min(chunk.len, (size_t)kFingerprint);
        hello.assign(chunk.data, chunk.data + take);
        break;
    }

    Flow &flow = touch(key, now_ms);
    bool restarts = !hello.empty() && !flow.hello.empty() && flow.hello != hello;
    if (restarts && (flow.resolved || flow.failed)) {
        flow = Flow{};
        flow.seen_ms = now_ms;
    }
    if (!hello.empty() && flow.hello.empty()) flow.hello = hello;
    Result result;

    if (bad) {
        flow.failed = true;
    } else if (!flow.resolved && !flow.failed && got) {
        result.fresh = absorb(flow, chunks);
    }

    if (flow.path == PATH_NONE && !flow.resolved) flow.path = PATH_PROXY;

    result.path = flow.path;
    result.has_sni = flow.resolved && !flow.sni.empty();
    if (result.has_sni) result.sni = flow.sni;
    return result;
}

void Tracker::pin(const Key &key, uint8_t path, uint64_t now_ms) {
    Flow &flow = touch(key, now_ms);
    if (flow.path == PATH_NONE || path == PATH_BLOCK) flow.path = path;
}

}  // namespace quic
