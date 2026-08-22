#ifndef QUIC_SNI_H_
#define QUIC_SNI_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace quic {

enum Path : uint8_t {
    PATH_NONE   = 0,
    PATH_PROXY  = 1,
    PATH_DIRECT = 2,
    PATH_BLOCK  = 3,
};

struct Config {
    uint32_t flow_timeout_ms = 60000;
    uint32_t max_flows = 65536;
    uint32_t max_crypto = 16384;
    uint32_t max_name = 63;
};

struct Key {
    uint32_t src = 0;
    uint32_t dst = 0;
    uint16_t sport = 0;
    uint16_t dport = 0;

    bool operator==(const Key &other) const {
        return src == other.src && dst == other.dst
            && sport == other.sport && dport == other.dport;
    }
};

struct KeyHash {
    size_t operator()(const Key &key) const {
        uint64_t value = (uint64_t)key.src << 32 | key.dst;
        value ^= (uint64_t)key.sport << 16 | key.dport;
        value *= 0x9e3779b97f4a7c15ull;
        return (size_t)(value ^ (value >> 32));
    }
};

struct Chunk {
    uint64_t offset;
    const uint8_t *data;
    size_t len;
};

struct Result {
    bool has_sni = false;
    bool fresh = false;
    std::string sni;
    uint8_t path = PATH_NONE;
};

class Tracker {
  public:
    void configure(const Config &config);
    Result classify(const Key &key, const uint8_t *data, size_t len, uint64_t now_ms);
    void pin(const Key &key, uint8_t path, uint64_t now_ms);
    size_t flows() const { return table_.size(); }

  private:
    struct Flow {
        std::vector<uint8_t> hello;
        uint8_t path = PATH_NONE;
        bool resolved = false;
        bool failed = false;
        std::string sni;
        std::vector<uint8_t> crypto;
        std::vector<std::pair<uint32_t, uint32_t>> spans;
        uint64_t seen_ms = 0;
    };

    Flow &touch(const Key &key, uint64_t now_ms);
    void sweep(uint64_t now_ms);
    bool collect(const uint8_t *data, size_t len, std::vector<Chunk> *chunks,
                 std::vector<std::vector<uint8_t>> *payloads, bool *bad);
    bool absorb(Flow &flow, const std::vector<Chunk> &chunks);

    Config config_;
    std::unordered_map<Key, Flow, KeyHash> table_;
    uint32_t since_sweep_ = 0;
};

bool sni_from_datagram(const uint8_t *data, size_t len, uint32_t max_name, std::string *sni);

}  // namespace quic

#endif  // QUIC_SNI_H_
