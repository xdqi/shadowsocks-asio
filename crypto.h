#ifndef SHADOWSOCKS_CRYPTO_H
#define SHADOWSOCKS_CRYPTO_H

#include "log.h"

#include <sodium.h>
#include <openssl/rand.h>
#include <arpa/inet.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>

template<typename T>
class Singleton
{
public:
  static T& instance()
  {
    static T singleton;
    return singleton;
  }

private:
  Singleton();
};

void hkdf_sha1(uint8_t *key, size_t key_len,
               const uint8_t *psk, size_t psk_len,
               const uint8_t *salt, size_t salt_len,
               const uint8_t *info, size_t info_len);

std::vector<uint8_t> password_to_key(const uint8_t *password, size_t pw_len, size_t key_len);

namespace Shadowsocks {
enum length {
  SHADOWSOCKS_HEADER_MAX_LENGTH = 1 + 255 + 2,
  SHADOWSOCKS_AEAD_PAYLOAD_MAX_LENGTH = 0x3fff,
  SHADOWSOCKS_AEAD_LENGTH_LENGTH = 2,
  SHADOWSOCKS_AEAD_TAG_LENGTH = 16
};

enum status {
  SHADOWSOCKS_NEW,
  SHADOWSOCKS_WAIT_LENGTH,
  SHADOWSOCKS_WAIT_PAYLOAD
};

class StreamCipher {

};

class AeadCipher;
extern std::unordered_map<std::string, AeadCipher *> aead_ciphers;

class AeadCipher {
  friend class AeadEncryptor;
  friend class AeadDecryptor;

public:
  size_t key_size_;
  size_t salt_size_;
  size_t nonce_size_;
  size_t tag_size_;

protected:
  AeadCipher(size_t key_size, size_t salt_size, size_t nonce_size, size_t tag_size) :
    key_size_(key_size), salt_size_(salt_size), nonce_size_(nonce_size), tag_size_(tag_size) {}

  virtual void aead_encrypt(uint8_t *ciphertext, size_t len_ciphertext,
                            const uint8_t *message, size_t len_message,
                            const uint8_t *ad, size_t len_ad,
                            const uint8_t *nonce, const uint8_t *key) = 0;

  virtual void aead_decrypt(uint8_t *message, size_t len_message,
                            const uint8_t *ciphertext, size_t len_ciphertext,
                            const uint8_t *ad, size_t len_ad,
                            const uint8_t *nonce, const uint8_t *key) = 0;

public:
  static const AeadCipher *const get_cipher(const std::string &name) {
    auto found = aead_ciphers.find(name);
    if (found != aead_ciphers.end()) {
      return aead_ciphers.at(name);
    } else {
      return nullptr;
    }
  }
};

class AeadEncryptor {
  AeadCipher *cipher_;
  uint8_t *salt_;
  uint8_t *key_;
  uint64_t *nonce_;
  size_t tag_size_;

public:
  explicit AeadEncryptor(const AeadCipher *cipher, const uint8_t *psk) {
    size_t salt_size = cipher->salt_size_;
    size_t key_size = cipher->key_size_;
    size_t nonce_uint64_size = ceil(cipher->nonce_size_ / 8.0);

    salt_ = new uint8_t[salt_size];
    key_ = new uint8_t[key_size];
    nonce_ = new uint64_t[nonce_uint64_size];
    tag_size_ = cipher->tag_size_;

    if (!RAND_bytes(salt_, salt_size)) {
      LOGF("server_salt_ generation failed");
    }

    hkdf_sha1(key_, key_size,
              psk, key_size,
              salt_, salt_size,
              (uint8_t *) "ss-subkey", 9);
    memset(nonce_, 0, cipher->nonce_size_);
  }

  const uint8_t *salt() {
    return salt_;
  };
  std::vector<uint8_t> encrypt_data(const uint8_t *message, size_t len_msg);
};


class AeadDecryptor {
  AeadCipher *cipher_;
  uint8_t *salt_;
  uint8_t *key_;
  uint64_t *nonce_;
  size_t tag_size_;


public:
  explicit AeadDecryptor(const AeadCipher *cipher, const uint8_t *psk, const uint8_t *salt) {
    size_t salt_size = cipher->salt_size_;
    size_t key_size = cipher->key_size_;
    size_t nonce_uint64_size = ceil(cipher->nonce_size_ / 8.0);

    salt_ = new uint8_t[salt_size];
    key_ = new uint8_t[key_size];
    nonce_ = new uint64_t[nonce_uint64_size];
    tag_size_ = cipher->tag_size_;

    memcpy(salt_, salt, salt_size);

    hkdf_sha1(key_, key_size,
              psk, key_size,
              salt_, salt_size,
              (uint8_t *) "ss-subkey", 9);
    memset(nonce_, 0, cipher->nonce_size_);
  }

  std::vector<uint8_t> decrypt_data(const uint8_t *ciphertext, size_t len_ciphertext) {
    std::vector<uint8_t> result(len_ciphertext - tag_size_);
    result.reserve(len_ciphertext - tag_size_); // TODO: redunant

    cipher_->aead_decrypt(result.data(), len_ciphertext - tag_size_,
                          ciphertext, len_ciphertext,
                          nullptr, 0,
                          reinterpret_cast<const uint8_t *>(nonce_), key_);
    nonce_[0]++;
    LOGV("decrypted data: ");
    hexdump(result);
    return result;
  }
};

typedef int (*SodiumAeadEncryptor)(unsigned char *c,
                                   unsigned long long *clen,
                                   const unsigned char *m,
                                   unsigned long long mlen,
                                   const unsigned char *ad,
                                   unsigned long long adlen,
                                   const unsigned char *nsec,
                                   const unsigned char *npub,
                                   const unsigned char *k);
typedef int (*SodiumAeadDecryptor)(unsigned char *m,
                                   unsigned long long *mlen,
                                   unsigned char *nsec,
                                   const unsigned char *c,
                                   unsigned long long clen,
                                   const unsigned char *ad,
                                   unsigned long long adlen,
                                   const unsigned char *npub,
                                   const unsigned char *k);
class SodiumAeadCipher : public AeadCipher {
  SodiumAeadEncryptor encryptor_;
  SodiumAeadDecryptor decryptor_;

public:
  SodiumAeadCipher(size_t key_size, size_t salt_size, size_t nonce_size, size_t tag_size,
                   SodiumAeadEncryptor encryptor, SodiumAeadDecryptor decryptor) :
    AeadCipher(key_size, salt_size, nonce_size, tag_size), encryptor_(encryptor), decryptor_(decryptor) {}

protected:
  void aead_encrypt(uint8_t *ciphertext, size_t len_ciphertext,
                    const uint8_t *message, size_t len_message,
                    const uint8_t *ad, size_t len_ad,
                    const uint8_t *nonce, const uint8_t *key) final {
    unsigned long long sodium_len = len_ciphertext;
    encryptor_(ciphertext, &sodium_len,
               message, len_message,
               ad, len_ad,
               nullptr, nonce, key);
  }

  void aead_decrypt(uint8_t *message, size_t len_message,
                    const uint8_t *ciphertext, size_t len_ciphertext,
                    const uint8_t *ad, size_t len_ad,
                    const uint8_t *nonce, const uint8_t *key) final {
    unsigned long long sodium_len = len_message;
    decryptor_(message, &sodium_len,
               nullptr,
               ciphertext, len_ciphertext,
               ad, len_ad,
               nonce, key);
  }
};

class SodiumChacha20IetfPoly1305Cipher : public SodiumAeadCipher {
public:
  SodiumChacha20IetfPoly1305Cipher() : SodiumAeadCipher(32, 32, 12, 16,
                                                        crypto_aead_chacha20poly1305_ietf_encrypt,
                                                        crypto_aead_chacha20poly1305_ietf_decrypt) {}
};

class SodiumAes256GcmCipher : public SodiumAeadCipher {
public:
  SodiumAes256GcmCipher() : SodiumAeadCipher(32, 32, 12, 16,
                                             crypto_aead_aes256gcm_encrypt,
                                             crypto_aead_aes256gcm_decrypt) {}
};

} // namespace Shadowsocks
#endif // SHADOWSOCKS_CRYPTO_H
