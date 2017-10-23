#include "crypto.h"
#include "log.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/md5.h>

std::vector<uint8_t> hkdf_sha1(const uint8_t *key, size_t key_len,
                                   const uint8_t *salt, size_t salt_len,
                                   const uint8_t *info, size_t info_len,
                                   size_t length) {
  std::vector<uint8_t> result(length);
  size_t result_length = length;

  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (EVP_PKEY_derive_init(pctx) <= 0) {
    LOGE("EVP_PKEY_derive_init failed\n");
    return {};
  }
  if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha1()) <= 0) {
    LOGE("EVP_PKEY_CTX_set_hkdf_md failed\n");
    return {};
  }
  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
    LOGE("EVP_PKEY_CTX_set1_hkdf_salt failed\n");
    return {};
  }
  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_len) <= 0) {
    LOGE("EVP_PKEY_CTX_set1_hkdf_key failed\n");
    return {};
  }
  if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
    LOGE("EVP_PKEY_CTX_add1_hkdf_info failed\n");
    return {};
  }
  if (EVP_PKEY_derive(pctx, result.data(), &result_length) <= 0) {
    LOGE("EVP_PKEY_derive failed\n");
    return {};
  }
  if (result_length != length) {
    LOGE("EVP_PKEY_derive length error\n");
    return {};
  }

  return result;
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
