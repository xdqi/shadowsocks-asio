#ifndef SHADOWSOCKS_CRYPTO_H
#define SHADOWSOCKS_CRYPTO_H

#include <memory>
#include <cstdint>

std::shared_ptr<uint8_t> hkdf_sha1(const uint8_t *key, size_t key_len,
                                   const uint8_t *salt, size_t salt_len,
                                   const uint8_t *info, size_t info_len,
                                   size_t length);


#endif // SHADOWSOCKS_CRYPTO_H
