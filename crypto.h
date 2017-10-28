#ifndef SHADOWSOCKS_CRYPTO_H
#define SHADOWSOCKS_CRYPTO_H

#include "log.h"

#include <arpa/inet.h>
#include <unordered_map>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cmath>

#ifdef SODIUM_FOUND
#include <sodium.h>
#endif

#ifdef OPENSSL_FOUND
#include <openssl/evp.h>
#include <openssl/rand.h>
#endif


namespace Socks5 {
enum version {
  SOCKS_VERSION_4 = 4,
  SOCKS_VERSION_5 = 5
};

enum status {
  SOCKS_NEW,              // Client connected and did nothing
  SOCKS_WAIT_METHODS,     // Client did not send authentication methods
  SOCKS_WAIT_REQUEST,     // Client did not send request
  SOCKS_WAIT_DSTADDR,
  SOCKS_WAIT_DOMAIN,
  SOCKS_WAIT_DSTPORT,
  SOCKS_ESTABLISHED,      // Connection Established
  SOCKS_WAIT_UDP_CLOSE,   // Wait for UDP association stopping
  SOCKS4_WAIT_DSTPORT_IP, // SOCKS4
  SOCKS4_WAIT_USERID,     // SOCKS4
  SOCKS4_WAIT_DOMAIN,     // SOCKS4a
};

enum authentication {
  SOCKS_AUTH_NO = 0,
  SOCKS_AUTH_GSSAPI = 1,
  SOCKS_AUTH_USERPASS = 2
};

enum address_type {
  SOCKS_ADDR_IPV4 = 1,
  SOCKS_ADDR_DOMAIN = 3,
  SOCKS_ADDR_IPV6 = 4
};

enum command {
  SOCKS_CONNECT = 1,
  SOCKS_BIND = 2,
  SOCKS_UDP_ASSOCIATE = 3
};

enum length {
  SOCKS_LENGTH_VERSION_NMETHOD = 2,
  SOCKS_LENGTH_REQUEST_UNTIL_ATYP = 4,
  SOCKS_LENGTH_ADDR_IPV4 = 4,
  SOCKS_LENGTH_ADDR_IPV6 = 16,
  SOCKS_LENGTH_PORT = 2,
  SOCKS4_LENGTH_DSTPORT_IP = 6
};

extern const uint8_t server_hello[2];
extern const uint8_t socks4_server_hello[8];
extern const uint8_t socks4_rejected[8];

extern const uint8_t reply_success[10];
extern const uint8_t reply_command_not_supported[10];
extern const uint8_t reply_address_type_not_supported[10];
}

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

void print_all_ciphers();

enum length {
  SHADOWSOCKS_HEADER_MAX_LENGTH = 1 + 255 + 2,
  SHADOWSOCKS_AEAD_PAYLOAD_MAX_LENGTH = 0x3fff,
  SHADOWSOCKS_AEAD_LENGTH_LENGTH = 2,
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
                            const uint8_t *nonce, const uint8_t *key) const = 0;

  virtual void aead_decrypt(uint8_t *message, size_t len_message,
                            const uint8_t *ciphertext, size_t len_ciphertext,
                            const uint8_t *ad, size_t len_ad,
                            const uint8_t *nonce, const uint8_t *key) const = 0;

public:
  static const AeadCipher *get_cipher(const std::string &name) {
    auto found = aead_ciphers.find(name);
    if (found != aead_ciphers.end()) {
      return aead_ciphers.at(name);
    } else {
      return nullptr;
    }
  }
};

class AeadEncryptor {
  const AeadCipher *cipher_;
  uint8_t *salt_;
  uint8_t *key_;
  uint64_t *nonce_;
  size_t tag_size_;

public:
  explicit AeadEncryptor(const AeadCipher *cipher, const uint8_t *psk): cipher_(cipher) {
    size_t salt_size = cipher->salt_size_;
    size_t key_size = cipher->key_size_;
    size_t nonce_uint64_size = ceil(cipher->nonce_size_ / 8.0);

    salt_ = new uint8_t[salt_size];
    key_ = new uint8_t[key_size];
    nonce_ = new uint64_t[nonce_uint64_size];
    tag_size_ = cipher->tag_size_;

#ifdef SODIUM_FOUND
    randombytes_buf(salt_, salt_size);
#elif defined(OPENSSL_FOUND)
    if (!RAND_bytes(salt_, salt_size)) {
      LOGF("server_salt_ generation failed");
    }
#endif

    hkdf_sha1(key_, key_size,
              psk, key_size,
              salt_, salt_size,
              (uint8_t *) "ss-subkey", 9);
    memset(nonce_, 0, cipher->nonce_size_);
  }

  ~AeadEncryptor() {
    delete []salt_;
    delete []key_;
    delete []nonce_;
  }

  const uint8_t *salt() {
    return salt_;
  };
  std::vector<uint8_t> encrypt_data(const uint8_t *message, size_t len_msg) {
    std::vector<uint8_t> result(Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + tag_size_ + len_msg + tag_size_);

    LOGV("message to encrypt");
    //hexdump(message, len_msg);

    // encrypt length
    uint16_t msg_len_msg = htons((uint16_t)len_msg);

    cipher_->aead_encrypt(result.data(), Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + tag_size_,
                          reinterpret_cast<const uint8_t *>(&msg_len_msg), Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH,
                          nullptr, 0,
                          reinterpret_cast<const uint8_t *>(nonce_), key_);
    nonce_[0]++;

    // encrypt message
    cipher_->aead_encrypt(result.data() + Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + tag_size_, len_msg + tag_size_,
                          message, len_msg,
                          nullptr, 0,
                          reinterpret_cast<const uint8_t *>(nonce_), key_);
    nonce_[0]++;
    return result;
  }


  std::vector<uint8_t> encrypt_packet(const uint8_t *message, size_t len_msg) {
    std::vector<uint8_t> nonce(cipher_->nonce_size_, 0);
    std::vector<uint8_t> result(Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + tag_size_ + len_msg + tag_size_);

    LOGV("packet to encrypt");
    //hexdump(message, len_msg);

    // encrypt message
    cipher_->aead_encrypt(result.data() + Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + tag_size_, len_msg + tag_size_,
                          message, len_msg,
                          nullptr, 0,
                          nonce.data(), key_);
    return result;
  }
};


class AeadDecryptor {
  const AeadCipher *cipher_;
  uint8_t *salt_;
  uint8_t *key_;
  uint64_t *nonce_;
  size_t tag_size_;


public:
  explicit AeadDecryptor(const AeadCipher *cipher, const uint8_t *psk, const uint8_t *salt): cipher_(cipher) {
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

  ~AeadDecryptor() {
    delete []salt_;
    delete []key_;
    delete []nonce_;
  }

  std::vector<uint8_t> decrypt_data(const uint8_t *ciphertext, size_t len_ciphertext) {
    std::vector<uint8_t> result(len_ciphertext - tag_size_);

    cipher_->aead_decrypt(result.data(), len_ciphertext - tag_size_,
                          ciphertext, len_ciphertext,
                          nullptr, 0,
                          reinterpret_cast<const uint8_t *>(nonce_), key_);
    nonce_[0]++;
    LOGV("decrypted data: ");
    //hexdump(result);
    return result;
  }

  std::vector<uint8_t> decrypt_packet(const uint8_t *ciphertext, size_t len_ciphertext) {
    std::vector<uint8_t> nonce(cipher_->nonce_size_, 0);
    std::vector<uint8_t> result(len_ciphertext - tag_size_);

    cipher_->aead_decrypt(result.data(), len_ciphertext - tag_size_,
                          ciphertext, len_ciphertext,
                          nullptr, 0,
                          nonce.data(), key_);
    LOGV("decrypted packet: ");
    //hexdump(result);
    return result;
  }
};

#ifdef SODIUM_FOUND
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
                    const uint8_t *nonce, const uint8_t *key) const {
    unsigned long long sodium_len = len_ciphertext;
    encryptor_(ciphertext, &sodium_len,
               message, len_message,
               ad, len_ad,
               nullptr, nonce, key);
  }

  void aead_decrypt(uint8_t *message, size_t len_message,
                    const uint8_t *ciphertext, size_t len_ciphertext,
                    const uint8_t *ad, size_t len_ad,
                    const uint8_t *nonce, const uint8_t *key) const {
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

#endif // SODIUM_FOUND

#ifdef OPENSSL_FOUND
class OpensslGcmAeadCipher : public AeadCipher {
  const EVP_CIPHER *cipher_;

public:
  OpensslGcmAeadCipher(size_t key_size, size_t salt_size, size_t nonce_size, size_t tag_size,
    const EVP_CIPHER *cipher) :
  AeadCipher(key_size, salt_size, nonce_size, tag_size), cipher_(cipher) {}

protected:
  void aead_encrypt(uint8_t *ciphertext, size_t /* len_ciphertext */,
                    const uint8_t *message, size_t len_message,
                    const uint8_t *ad, size_t len_ad,
                    const uint8_t *nonce, const uint8_t *key) const {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
      LOGE("EVP_CIPHER_CTX_new failed");
    };

    /* Initialise the encryption operation. */
    if(1 != EVP_EncryptInit_ex(ctx, cipher_, NULL, NULL, NULL)) {
      LOGE("EVP_EncryptInit_ex init cipher failed");
    }

    /* Set IV length if default 12 bytes (96 bits) is not appropriate */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_size_, NULL)) {
      LOGE("EVP_CTRL_GCM_SET_IVLEN set nonce failed");
    }

    /* Initialise key and IV */
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) {
      LOGE("EVP_EncryptInit_ex set key and nonce failed");
    }

    /* Provide any AAD data. This can be called zero or more times as
     * required
     */
    if (len_ad) {
      if (1 != EVP_EncryptUpdate(ctx, NULL, &len, ad, len_ad)) {
        LOGE("EVP_EncryptUpdate set ad failed");
      }
    }

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, message, len_message)) {
      LOGE("EVP_EncryptUpdate encryption failed");
    }
    ciphertext_len = len;

    /* Finalise the encryption. Normally ciphertext bytes may be written at
     * this stage, but this does not occur in GCM mode
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
      LOGE("EVP_EncryptFinal_ex failed");
    }
    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_size_, ciphertext + ciphertext_len)) {
      LOGE("EVP_CTRL_GCM_GET_TAG write tag failed");
    }

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
  }

  void aead_decrypt(uint8_t *message, size_t len_message,
                    const uint8_t *ciphertext, size_t /* len_ciphertext */,
                    const uint8_t *ad, size_t len_ad,
                    const uint8_t *nonce, const uint8_t *key) const {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) {
      LOGE("EVP_CIPHER_CTX_new failed\n");
    };

    /* Initialise the decryption operation. */
    if(!EVP_DecryptInit_ex(ctx, cipher_, NULL, NULL, NULL)) {
      LOGE("EVP_DecryptInit_ex init cipher failed");
    }

    /* Set IV length. Not necessary if this is 12 bytes (96 bits) */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce_size_, NULL)) {
      LOGE("EVP_CTRL_GCM_SET_IVLEN set nonce failed");
    }

    /* Initialise key and IV */
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) {
      LOGE("EVP_DecryptInit_ex set key and nonce failed");
    }
    /* Provide any AAD data. This can be called zero or more times as
     * required
     */

    if (len_ad) {
      if (!EVP_DecryptUpdate(ctx, NULL, &len, ad, len_ad)) {
        LOGE("EVP_DecryptUpdate set ad failed");
      }
    }

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(!EVP_DecryptUpdate(ctx, message, &len, ciphertext, len_message)) {
      LOGE("EVP_DecryptUpdate decryption failed");
    }
    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later*/
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_size_, (void *) (ciphertext + len_message))) {
      LOGE("EVP_CTRL_GCM_SET_TAG set expected tag failed");
    }

    /* Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal_ex(ctx, message, &len);

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
      /* Success */
      plaintext_len += len;
      // TODO: return plaintext length
    }
    else
    {
      LOGE("Message forged");
      memset(message, 0xcc, len_message);
      /* Verify failed */
    }
  }
};

class OpensslChacha20IetfPoly1305Cipher : public OpensslGcmAeadCipher {
public:
  OpensslChacha20IetfPoly1305Cipher() : OpensslGcmAeadCipher(32, 32, 12, 16, EVP_chacha20_poly1305()) {}
};

class OpensslAes256GcmCipher : public OpensslGcmAeadCipher {
public:
  OpensslAes256GcmCipher() : OpensslGcmAeadCipher(32, 32, 12, 16, EVP_aes_256_gcm()) {}
};

class OpensslAes192GcmCipher : public OpensslGcmAeadCipher {
public:
  OpensslAes192GcmCipher() : OpensslGcmAeadCipher(24, 24, 12, 16, EVP_aes_192_gcm()) {}
};

class OpensslAes128GcmCipher : public OpensslGcmAeadCipher {
public:
  OpensslAes128GcmCipher() : OpensslGcmAeadCipher(16, 16, 12, 16, EVP_aes_128_gcm()) {}
};

#endif // OPENSSL_FOUND

} // namespace Shadowsocks
#endif // SHADOWSOCKS_CRYPTO_H
