#include "crypto.h"
#include "log.h"

#include <cstring>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/md5.h>

namespace Socks5 {
const uint8_t server_hello[2] = {0x05, 0x00};
const uint8_t socks4_server_hello[8] = {0x00, 90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t socks4_rejected[8] = {0x00, 91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

const uint8_t reply_success[10] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t reply_command_not_supported[10] = {0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t reply_address_type_not_supported[10] = {0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
} // namespace Socks5

void hkdf_sha1(uint8_t *key, size_t key_len,
               const uint8_t *psk, size_t psk_len,
               const uint8_t *salt, size_t salt_len,
               const uint8_t *info, size_t info_len) {
  size_t result_length = key_len;

  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (EVP_PKEY_derive_init(pctx) <= 0) {
    LOGE("EVP_PKEY_derive_init failed\n");
    return;
  }
  if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha1()) <= 0) {
    LOGE("EVP_PKEY_CTX_set_hkdf_md failed\n");
    return;
  }
  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
    LOGE("EVP_PKEY_CTX_set1_hkdf_salt failed\n");
    return;
  }
  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, psk, psk_len) <= 0) {
    LOGE("EVP_PKEY_CTX_set1_hkdf_key failed\n");
    return;
  }
  if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
    LOGE("EVP_PKEY_CTX_add1_hkdf_info failed\n");
    return;
  }
  if (EVP_PKEY_derive(pctx, key, &result_length) <= 0) {
    LOGE("EVP_PKEY_derive failed\n");
    return;
  }
  if (result_length != key_len) {
    LOGE("EVP_PKEY_derive length error\n");
    return;
  }
}

std::vector<uint8_t> password_to_key(const uint8_t *password, size_t pw_len, size_t key_len) {
  std::vector<uint8_t> result(key_len);
  size_t generated_len = 0;

  MD5_CTX ctx;
  while (generated_len < key_len) {
    MD5_Init(&ctx);
    if (generated_len) {
      MD5_Update(&ctx, result.data() + generated_len - 16, 16);
    }
    MD5_Update(&ctx, password, pw_len);
    MD5_Final(result.data() + generated_len, &ctx);
    generated_len += 16;
  }
  return result;
}

namespace Shadowsocks {
std::unordered_map<std::string, AeadCipher *> aead_ciphers {
#ifdef SODIUM_FOUND
  {"chacha20-ietf-poly1305", &Singleton<SodiumChacha20IetfPoly1305Cipher>::instance()},
  {"aes-256-gcm",            &Singleton<SodiumAes256GcmCipher>::instance()},
#elif defined(OPENSSL_FOUND)
  {"chacha20-ietf-poly1305", &Singleton<OpensslChacha20IetfPoly1305Cipher>::instance()},
  {"aes-256-gcm",            &Singleton<OpensslAes256GcmCipher>::instance()},
#endif

#ifdef SODIUM_FOUND
  {"sodium::chacha20-ietf-poly1305",  &Singleton<SodiumChacha20IetfPoly1305Cipher>::instance()},
  {"sodium::aes-256-gcm",              &Singleton<SodiumAes256GcmCipher>::instance()},
#endif

#ifdef OPENSSL_FOUND
  {"aes-192-gcm",                     &Singleton<OpensslAes192GcmCipher>::instance()},
  {"aes-128-gcm",                     &Singleton<OpensslAes128GcmCipher>::instance()},
  {"openssl::chacha20-ietf-poly1305", &Singleton<OpensslChacha20IetfPoly1305Cipher>::instance()},
  {"openssl::aes-256-gcm",            &Singleton<OpensslAes256GcmCipher>::instance()},
  {"openssl::aes-192-gcm",            &Singleton<OpensslAes192GcmCipher>::instance()},
  {"openssl::aes-128-gcm",            &Singleton<OpensslAes128GcmCipher>::instance()},
#endif

}; // aead_ciphers

void print_all_ciphers() {
#ifdef SODIUM_FOUND
  printf("Built with libsodium " SODIUM_VERSION_STRING ".\n");
#endif

#ifdef OPENSSL_FOUND
  printf("Built with " OPENSSL_VERSION_TEXT ".\n");
#endif

  printf("\nSupported ciphers: \n\n");
  for (auto &cipher: aead_ciphers) {
    printf("  %s\n", cipher.first.c_str());
  }
}

}