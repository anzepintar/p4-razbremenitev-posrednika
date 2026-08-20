#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "quic_sni.h"

namespace {

bool unhex(const std::string &text, std::vector<uint8_t> *out) {
    if (text.size() % 2 != 0) return false;
    out->clear();
    for (size_t i = 0; i < text.size(); i += 2) {
        char pair[3] = {text[i], text[i + 1], 0};
        char *end = nullptr;
        long value = strtol(pair, &end, 16);
        if (end != pair + 2) return false;
        out->push_back((uint8_t)value);
    }
    return true;
}

}  // namespace

int main(int argc, char **argv) {
    quic::Config config;
    if (argc > 1) config.max_name = (uint32_t)atoi(argv[1]);

    quic::Tracker tracker;
    tracker.configure(config);

    char line[1 << 16];
    uint64_t clock = 0;
    while (fgets(line, sizeof(line), stdin) != nullptr) {
        std::string text(line);
        while (!text.empty() && (text.back() == '\n' || text.back() == '\r'))
            text.pop_back();
        if (text.empty()) continue;

        unsigned flow = 0;
        size_t split = text.find(' ');
        if (split != std::string::npos) {
            flow = (unsigned)atoi(text.substr(0, split).c_str());
            text = text.substr(split + 1);
        }

        quic::Key key;
        key.src = 0x0a00010a;
        key.dst = 0x0a00020a;
        key.sport = (uint16_t)(40000 + flow);
        key.dport = 443;

        std::vector<uint8_t> data;
        if (!unhex(text, &data)) {
            printf("error\n");
            continue;
        }
        quic::Result result = tracker.classify(key, data.data(), data.size(), ++clock);
        printf("%s %s %u\n", result.fresh ? "fresh" : "cached",
               result.has_sni ? result.sni.c_str() : "-", result.path);
        fflush(stdout);
    }
    return 0;
}
