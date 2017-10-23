#include "crypto.h"
#include "log.h"

#include <cstring>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/md5.h>

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
std::unordered_map<std::string, AeadCipher *> aead_ciphers{
  {"chacha20-ietf-poly1305", &Singleton<SodiumChacha20IetfPoly1305Cipher>::instance()},
  {"aes-256-gcm",            &Singleton<SodiumAes256GcmCipher>::instance()},
};


std::vector<uint8_t> AeadEncryptor::encrypt_data(const uint8_t *message, size_t len_msg) {
  //std::vector<uint8_t> result(Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + tag_size_ + len_msg + tag_size_);
  //result.reserve(Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + tag_size_ + len_msg + tag_size_); // TODO: redunant

  uint8_t tmp[Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + tag_size_ + len_msg + tag_size_];
  LOGV("message to encrypt");
  hexdump(message, len_msg);

  // encrypt length
  LOGV("aaaaa");

  uint16_t msg_len_msg = htons((uint16_t)len_msg);
  LOGV("bbbbb");

  cipher_->aead_encrypt(tmp, Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + tag_size_,
                        reinterpret_cast<const uint8_t *>(&msg_len_msg), Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH,
                        nullptr, 0,
                        reinterpret_cast<const uint8_t *>(nonce_), key_);

  LOGV("ccccc");
  nonce_[0]++;

  // encrypt message
  cipher_->aead_encrypt(tmp + Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + tag_size_, len_msg + tag_size_,
                        message, len_msg,
                        nullptr, 0,
                        reinterpret_cast<const uint8_t *>(nonce_), key_);
  nonce_[0]++;
  return std::vector<uint8_t>(tmp, tmp+Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + tag_size_ + len_msg + tag_size_);
}
}