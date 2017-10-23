#ifndef SHADOWSOCKS_LOG_H
#define SHADOWSOCKS_LOG_H

#include <cstdio>
#include <cstdint>
#include <cctype>
#include <vector>

#define LOG(level, fmt, ...) do {fprintf(stderr, "[%7s] [%s:%d] ", #level, __func__, __LINE__); fprintf(stderr, fmt, ##__VA_ARGS__); fprintf(stderr, "\n"); } while (false)

#define LOGD(fmt, ...) LOG(debug, fmt, ##__VA_ARGS__)
#define LOGV(fmt, ...) LOG(verbose, fmt, ##__VA_ARGS__)
#define LOGI(fmt, ...) LOG(info, fmt, ##__VA_ARGS__)
#define LOGW(fmt, ...) LOG(warn, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) LOG(error, fmt, ##__VA_ARGS__)
#define LOGF(fmt, ...) LOG(fatal, fmt, ##__VA_ARGS__)

inline void hexdump(const void *input, size_t length) {
  const uint8_t *buf = reinterpret_cast<const uint8_t *>(input);
  for (int i = 0; i < length; i += 16) {
    fprintf(stderr, "%04X  ", i);
    for (int j = 0; j < 16; j++) {
      if (i + j < length) {
        fprintf(stderr, "%02x ", buf[i + j]);
      } else {
        fprintf(stderr, "   ");
      }
      if (j == 7) {
        fprintf(stderr, " ");
      }
    }
    fprintf(stderr, "  ");

    for (int j = 0; j < 16; j++) {
      if (i + j < length) {
        fprintf(stderr, "%c", isprint(buf[i + j]) ? buf[i + j] : '.');
      }
    }
    fprintf(stderr, "\n");
  }
}

inline void hexdump(const std::vector<uint8_t>& data) {
  hexdump(data.data(), data.size());
}

#endif //SHADOWSOCKS_LOG_H
