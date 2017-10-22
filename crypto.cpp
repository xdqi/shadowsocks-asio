#include "crypto.h"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/md5.h>

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

  //EVP_PKEY_CTX_free(pctx);
  return result;
}

std::shared_ptr<uint8_t> password_to_key(const uint8_t *password, size_t pw_len, size_t key_len) {
  std::shared_ptr<uint8_t> result = std::make_shared<uint8_t>(32);
  /*uint8_t iv[32];
  if (EVP_BytesToKey(EVP_aes_256_cfb(), EVP_md5(), nullptr, password, pw_len, 1, result.get(), iv) != key_len) {
    fprintf(stderr, "EVP_BytesToKey failed\n");
  }*/
  size_t generated_len = 0;
  MD5_CTX ctx;
  while (generated_len < key_len) {
    fprintf(stderr, "generated %zu bytes\n", generated_len);
    MD5_Init(&ctx);
    if (generated_len) {
      MD5_Update(&ctx, result.get(), generated_len);
    }
    MD5_Update(&ctx, password, pw_len);
    MD5_Final(result.get() + generated_len, &ctx);
    generated_len += 16;
  }
  fprintf(stderr, "final: generated %zu bytes\n", generated_len);
  return result;
}
