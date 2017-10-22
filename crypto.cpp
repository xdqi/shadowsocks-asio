#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>

std::shared_ptr<uint8_t> hkdf_sha1(const uint8_t *key, size_t key_len,
                                   const uint8_t *salt, size_t salt_len,
                                   const uint8_t *info, size_t info_len,
                                   size_t length) {
  std::shared_ptr<uint8_t> result = std::make_shared<uint8_t>(length);
  size_t result_length = length;

  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (EVP_PKEY_derive_init(pctx) <= 0) {
    fprintf(stderr, "EVP_PKEY_derive_init failed\n");
    return nullptr;
  }
  if (EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha1()) <= 0) {
    fprintf(stderr, "EVP_PKEY_CTX_set_hkdf_md failed\n");
    return nullptr;
  }
  if (EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len) <= 0) {
    fprintf(stderr, "EVP_PKEY_CTX_set1_hkdf_salt failed\n");
    return nullptr;
  }
  if (EVP_PKEY_CTX_set1_hkdf_key(pctx, key, key_len) <= 0) {
    fprintf(stderr, "EVP_PKEY_CTX_set1_hkdf_key failed\n");
    return nullptr;
  }
  if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len) <= 0) {
    fprintf(stderr, "EVP_PKEY_CTX_add1_hkdf_info failed\n");
    return nullptr;
  }
  if (EVP_PKEY_derive(pctx, result.get(), &result_length) <= 0) {
    fprintf(stderr, "EVP_PKEY_derive failed\n");
    return nullptr;
  }
  if (result_length != length) {
    fprintf(stderr, "EVP_PKEY_derive length error\n");
    return nullptr;
  }

  EVP_PKEY_CTX_free(pctx);
  return result;
}