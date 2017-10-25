#include "crypto.h"

bool test_hmac_sha1() {
  const uint8_t correct[16] = {0x64, 0x5C, 0xE2, 0x06, 0x81, 0x55, 0xDD, 0x5B, 0x53, 0x7E, 0xDD, 0x04, 0xA7, 0xE0, 0xD2, 0x35 };

  const uint8_t *key = (const uint8_t *) "haha";
  const uint8_t *salt = (const uint8_t *) "0123456789abcdef";
  const uint8_t *info = (const uint8_t *) "ss-subkey";

  auto res = hkdf_sha1(key, 4, salt, 16, info, 9, 16);
  return !memcmp(res.get(), correct, 16);
}