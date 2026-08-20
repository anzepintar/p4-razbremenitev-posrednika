#include <bm/bm_sim/extern.h>
#include <bm/bm_sim/packet.h>

#include <chrono>
#include <cstdint>
#include <vector>

#include "quic_sni.h"

namespace {

uint64_t now_ms() {
    using namespace std::chrono;
    return (uint64_t)duration_cast<milliseconds>(
        steady_clock::now().time_since_epoch()).count();
}

quic::Key make_key(const bm::Data &src, const bm::Data &dst,
                   const bm::Data &sport, const bm::Data &dport) {
    quic::Key key;
    key.src = src.get<uint32_t>();
    key.dst = dst.get<uint32_t>();
    key.sport = sport.get<uint16_t>();
    key.dport = dport.get<uint16_t>();
    return key;
}

}  // namespace

class QuicSni : public bm::ExternType {
  public:
    BM_EXTERN_ATTRIBUTES {
        BM_EXTERN_ATTRIBUTE_ADD(flow_timeout_ms);
        BM_EXTERN_ATTRIBUTE_ADD(max_flows);
        BM_EXTERN_ATTRIBUTE_ADD(max_crypto);
        BM_EXTERN_ATTRIBUTE_ADD(max_name);
    }

    void init() override {
        quic::Config config;
        config.flow_timeout_ms = flow_timeout_ms.get<uint32_t>();
        config.max_flows = max_flows.get<uint32_t>();
        config.max_crypto = max_crypto.get<uint32_t>();
        config.max_name = max_name.get<uint32_t>();
        tracker_.configure(config);
    }

    void classify(const bm::Data &src, const bm::Data &dst,
                  const bm::Data &sport, const bm::Data &dport,
                  const bm::Data &length,
                  bm::Field &sni, bm::Data &state, bm::Data &path) {
        const bm::Packet &packet = get_packet();
        size_t len = packet.get_data_size();
        size_t udp = length.get<uint32_t>();
        if (udp >= 8 && udp - 8 < len) len = udp - 8;

        quic::Result result = tracker_.classify(
            make_key(src, dst, sport, dport),
            (const uint8_t *)packet.data(), len, now_ms());

        path.set(result.path);

        std::vector<char> key((size_t)sni.get_nbytes(), 0);
        bool found = result.has_sni && result.sni.size() <= key.size()
            && (result.fresh || result.path == quic::PATH_NONE);
        if (found) {
            std::copy(result.sni.begin(), result.sni.end(),
                      key.end() - (long)result.sni.size());
        }
        state.set(found ? 1 : 0);
        sni.set(key.data(), (int)key.size());
    }

    void pin(const bm::Data &src, const bm::Data &dst,
             const bm::Data &sport, const bm::Data &dport,
             const bm::Data &path) {
        tracker_.pin(make_key(src, dst, sport, dport),
                     (uint8_t)path.get<uint32_t>(), now_ms());
    }

  private:
    bm::Data flow_timeout_ms{60000};
    bm::Data max_flows{65536};
    bm::Data max_crypto{16384};
    bm::Data max_name{63};
    quic::Tracker tracker_;
};

BM_REGISTER_EXTERN(QuicSni);
BM_REGISTER_EXTERN_METHOD(QuicSni, classify,
                          const bm::Data &, const bm::Data &, const bm::Data &,
                          const bm::Data &, const bm::Data &,
                          bm::Field &, bm::Data &, bm::Data &);
BM_REGISTER_EXTERN_METHOD(QuicSni, pin,
                          const bm::Data &, const bm::Data &, const bm::Data &,
                          const bm::Data &, const bm::Data &);

int quic_sni_module_ = 0;
