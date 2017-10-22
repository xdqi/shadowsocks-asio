#ifndef SHADOWSOCKS_CRYPTO_H
#define SHADOWSOCKS_CRYPTO_H

#include <memory>
#include <cstdint>

std::shared_ptr<uint8_t> hkdf_sha1(const uint8_t *key, size_t key_len,
                                   const uint8_t *salt, size_t salt_len,
                                   const uint8_t *info, size_t info_len,
                                   size_t length);

std::shared_ptr<uint8_t> password_to_key(const uint8_t *password, size_t pw_len, size_t key_len);
namespace Shadowsocks {

class StreamCipher {

};

struct AEADCipher {
  uint8_t key_size;
  uint8_t salt_size;
  uint8_t nonce_size;
  uint8_t tag_size;

};

}
#endif // SHADOWSOCKS_CRYPTO_H
