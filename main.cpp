// #define BOOST_ASIO_ENABLE_HANDLER_TRACKING
#define _GLIBCXX_USE_INT128

#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <utility>
#include <cstdint>
#include <functional>
#include <boost/asio.hpp>

#include "crypto.h"
#include <sodium.h>
#include <openssl/rand.h>
#include "log.h"

using boost::asio::ip::tcp;

namespace Socks5 {
enum status {
  SOCKS_NEW,            // Client connected and did nothing
  SOCKS_WAIT_REQUEST,   // Client did not send request
  SOCKS_WAIT_DSTADDR,
  SOCKS_WAIT_DOMAIN,
  SOCKS_WAIT_DSTPORT,
  SOCKS_ESTABLISHED     // Connection Established
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
  SOCKS_LENGTH_CLIENT_HELLO = 3,
  SOCKS_LENGTH_REQUEST_UNTIL_ATYP = 4,
  SOCKS_LENGTH_ADDR_IPV4 = 4,
  SOCKS_LENGTH_ADDR_IPV6 = 16,
  SOCKS_LENGTH_PORT = 2,
};

const uint8_t client_hello[3] = {0x05, 0x01, 0x00};
const uint8_t server_hello[2] = {0x05, 0x00};

const uint8_t reply_success[10] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t reply_command_not_supported[10] = {0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
const uint8_t reply_address_type_not_supported[10] = {0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
}

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
}

class session : public std::enable_shared_from_this<session> {
public:
  session(boost::asio::io_service& io_service, tcp::socket socket,
          const std::string& server_host, const std::string& server_port)
    : server_socket_(std::move(socket)),
      client_socket_(io_service),
      resolver_(io_service),
      query_(server_host, server_port),
      socks_status_(Socks5::SOCKS_NEW),
      shadowsocks_status_(Shadowsocks::SHADOWSOCKS_NEW),
      server_data_{0},
      client_data_{0},
      ss_target_address{0},
      nonce_send{0},
      nonce_recv{0}
  {
  }

  void start() {
    set_up();
  }

  ~session() {
    LOGV("dtor session %p socket %p\n", this, &server_socket_);
  }

private:
  tcp::socket server_socket_;
  tcp::socket client_socket_;

  tcp::resolver resolver_;
  tcp::resolver::query query_;

  enum Socks5::status socks_status_;
  enum Shadowsocks::status shadowsocks_status_;

  uint8_t server_data_[Shadowsocks::SHADOWSOCKS_AEAD_PAYLOAD_MAX_LENGTH];
  uint8_t client_data_[Shadowsocks::SHADOWSOCKS_AEAD_PAYLOAD_MAX_LENGTH];
  uint8_t ss_target_address[Shadowsocks::SHADOWSOCKS_HEADER_MAX_LENGTH];
  uint8_t server_salt_[32];
  uint8_t server_key_[32];
  uint8_t client_salt_[32];
  uint8_t client_key_[32];
  int ss_target_written = 0;
  uint64_t nonce_send[2];
  uint64_t nonce_recv[2];

  void set_up() {
    auto self(shared_from_this());
    LOGV("session %p socket %p\n", this, &server_socket_);

    read_from_socks5_client(Socks5::SOCKS_LENGTH_CLIENT_HELLO);
  }

  void connect_to_ss_server(std::function<void ()> callback) {
    auto self(shared_from_this());
    resolver_.async_resolve(query_,
      [this, self, callback](const boost::system::error_code& resolve_error_code, tcp::resolver::iterator iter) {
        if (resolve_error_code) {
          LOGE("to ss-server async_resolve %s", resolve_error_code.message().c_str());
          return;
        }
        boost::asio::async_connect(client_socket_, iter,
          [this, self, callback](const boost::system::error_code& connect_error_code, tcp::resolver::iterator) {
            if (connect_error_code) {
              std::cerr << "to ss-server async_connect: " << connect_error_code.message() << std::endl;
              return;
            }
            LOGV("connected to ss-server");
            read_from_ss_server(32); // TODO: salt length
            init_connection_with_ss_server(callback);
        });
      });

  }

  void read_from_ss_server(size_t read_len) {
    auto self(shared_from_this());
    boost::asio::async_read(client_socket_, boost::asio::buffer(client_data_, read_len),
      [this, self](const boost::system::error_code& read_error_code, std::size_t length) {
        if (read_error_code) {
          std::cerr << "from ss-server async_read: " << read_error_code.message() << std::endl;
          return;
        }
        LOGV("Read from ss-server %zu bytes", length);
        switch (shadowsocks_status_) {
          case Shadowsocks::SHADOWSOCKS_NEW: {
            memcpy(client_salt_, client_data_, length);
            auto base_key = password_to_key((uint8_t *)"233", 3, 32);
            auto new_key = hkdf_sha1(base_key.data(), 32, client_salt_, sizeof client_salt_, (uint8_t *) "ss-subkey", 9, 32);
            memcpy(client_key_, new_key.data(), 32);
            shadowsocks_status_ = Shadowsocks::SHADOWSOCKS_WAIT_LENGTH;
            read_from_ss_server(Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + crypto_aead_chacha20poly1305_IETF_ABYTES);
          }
            return;
          case Shadowsocks::SHADOWSOCKS_WAIT_LENGTH: {
            uint16_t payload_length;
            unsigned long long payload_length_len;
            if (crypto_aead_chacha20poly1305_ietf_decrypt((uint8_t *)&payload_length, &payload_length_len, nullptr, client_data_, length, nullptr, 0, (uint8_t *)&nonce_recv, client_key_) != 0) {
              LOGE("read_from_ss_server length decryption failed");
              // TODO: fail it
              return;
            }
            nonce_recv[0]++;
            LOGV("read_from_ss_server payload length: %u", ntohs(payload_length));
            shadowsocks_status_ = Shadowsocks::SHADOWSOCKS_WAIT_PAYLOAD;
            read_from_ss_server(ntohs(payload_length) + crypto_aead_chacha20poly1305_IETF_ABYTES);
          }
            return;
          case Shadowsocks::SHADOWSOCKS_WAIT_PAYLOAD: {
            uint8_t data[length];
            unsigned long long payload_length = length;
            if (crypto_aead_chacha20poly1305_ietf_decrypt(data, &payload_length, nullptr, client_data_, length, nullptr, 0, (uint8_t *)&nonce_recv, client_key_) != 0) {
              LOGE("read_from_ss_server content decryption failed");
              // TODO: fail it
              return;
            }
            nonce_recv[0]++;
            LOGV("read_from_ss_server payload %zu bytes: ", payload_length);
            hexdump(data, payload_length);
            shadowsocks_status_ = Shadowsocks::SHADOWSOCKS_WAIT_LENGTH;

            boost::asio::async_write(server_socket_, boost::asio::buffer(data, payload_length),
              [this, self](const boost::system::error_code& write_error_code, std::size_t wrote_len) {
                if (write_error_code) {
                  std::cerr << "to server async_write: " << write_error_code.message() << std::endl;
                  return;
                }
                read_from_ss_server(Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + crypto_aead_chacha20poly1305_IETF_ABYTES);
              }
            );
          }
            return;
        }
      }
    );
  }

  void init_connection_with_ss_server(const std::function<void ()> &callback) {
    auto self(shared_from_this());
    if (!RAND_bytes(server_salt_, sizeof server_salt_)) {
      LOGF("server_salt_ generation failed");
      return;
    }
    //memset(server_salt_, 32, 1);

    auto base_key = password_to_key((uint8_t *)"233", 3, 32);

    auto new_key = hkdf_sha1(base_key.data(), 32, server_salt_, sizeof server_salt_, (uint8_t *) "ss-subkey", 9, 32);
    memcpy(server_key_, new_key.data(), 32);
    boost::asio::async_write(client_socket_, boost::asio::buffer(server_salt_, sizeof server_salt_),
      [this, self, callback](const boost::system::error_code& write_error_code, std::size_t wrote_len) {
        if (write_error_code) {
          std::cerr << "to server async_write: " << write_error_code.message() << std::endl;
          return;
        }
        // TODO: how to do callback
        callback();
      }
    );
  }

  void send_to_ss_server(const uint8_t *content, size_t length, const std::function<void ()> &callback) {
    auto self(shared_from_this());
    unsigned long long len_len = Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + crypto_aead_chacha20poly1305_IETF_ABYTES;
    uint8_t len_ciphertext[len_len];
    uint16_t len_short = htons((uint16_t)length);
    crypto_aead_chacha20poly1305_ietf_encrypt(len_ciphertext, &len_len,
                                              (uint8_t *)&len_short, 2,
                                              nullptr, 0,
                                              nullptr, (uint8_t *)&nonce_send, server_key_);
    LOGV("nonce_send when len:");
    hexdump(&nonce_send, 12);
    nonce_send[0]++;

    // encrypt length
    unsigned long long data_len = length + crypto_aead_chacha20poly1305_IETF_ABYTES;
    uint8_t data_ciphertext[data_len];
    crypto_aead_chacha20poly1305_ietf_encrypt(data_ciphertext, &data_len,
                                              content, length,
                                              nullptr, 0,
                                              nullptr, (uint8_t *)&nonce_send, server_key_);
    LOGV("out ciphertext: ");
    hexdump(data_ciphertext, data_len);

    LOGV("nonce_send when payload:");
    hexdump(&nonce_send, 12);

    nonce_send[0]++;
    // encrypt data
    boost::asio::async_write(client_socket_, std::vector<boost::asio::mutable_buffer>{{len_ciphertext, len_len}, {data_ciphertext, data_len}},
      [this, self, callback](const boost::system::error_code& write_error_code, std::size_t wrote_len) {
        if (write_error_code) {
          std::cerr << "to server async_write: " << write_error_code.message() << std::endl;
          return;
        }
        callback();
      }
    );
  }

  void read_some_from_socks5_client(size_t read_len) {
    auto self(shared_from_this());
    server_socket_.async_read_some(boost::asio::buffer(server_data_, read_len),
      [this, self](const boost::system::error_code& read_error_code, std::size_t length) {
        if (read_error_code) {
          std::cerr << "from client async_read_some: " << read_error_code.message() << std::endl;
          return;
        }
        LOGV("async_read_some Received %zu bytes from client: ", length);
        hexdump(server_data_, length);
        send_to_ss_server(server_data_, length, [=] {
          read_some_from_socks5_client(Shadowsocks::SHADOWSOCKS_AEAD_PAYLOAD_MAX_LENGTH);
        });
      }
    );
  }

  void read_from_socks5_client(size_t read_len) {
    auto self(shared_from_this());
    boost::asio::async_read(server_socket_, boost::asio::buffer(server_data_, read_len),
      [this, self](const boost::system::error_code& read_error_code, std::size_t length) {
        if (read_error_code) {
          std::cerr << "from client async_read: " << read_error_code.message() << std::endl;
          return;
        }
        switch (socks_status_) {
          case Socks5::SOCKS_NEW: {
            if (memcmp(server_data_, Socks5::client_hello, sizeof(Socks5::client_hello)) == 0) {
              boost::asio::async_write(server_socket_, boost::asio::buffer(Socks5::server_hello, sizeof(Socks5::server_hello)),
                [this, self](const boost::system::error_code &write_error_code, std::size_t /*length*/) {
                  if (write_error_code) {
                    std::cerr << "to client async_write: SOCKS5 handshake failed " << write_error_code.message() << std::endl;
                    return;
                  }
                  socks_status_ = Socks5::SOCKS_WAIT_REQUEST;
                  read_from_socks5_client(Socks5::SOCKS_LENGTH_REQUEST_UNTIL_ATYP);
                }
              );
            } else {
              LOGE("from client async_read_some: SOCKS5 handshake failed");
            }
          }
            return;
          case Socks5::SOCKS_WAIT_REQUEST: {
            if (server_data_[0] == 5) {
              if (server_data_[1] != Socks5::SOCKS_CONNECT) { // CONNECT supported only
                LOGE("from client async_read_some: SOCKS5 CMD %u not supported", server_data_[1]);
                boost::asio::async_write(server_socket_, boost::asio::buffer(Socks5::reply_command_not_supported, sizeof(Socks5::reply_command_not_supported)),
                  [this, self](const boost::system::error_code &write_error_code, std::size_t /*length*/) {
                    if (write_error_code) {
                      std::cerr << "to client async_write: SOCKS5 close failed " << write_error_code.message() << std::endl;
                    }
                  }
                );
                return;
              }

              int ss_header_length = 0;
              switch (server_data_[3]) {
                case Socks5::SOCKS_ADDR_IPV4:
                  ss_header_length = 4;
                  break;
                case Socks5::SOCKS_ADDR_IPV6:
                  ss_header_length = 16;
                  break;
                case Socks5::SOCKS_ADDR_DOMAIN:
                  ss_header_length = 1;
                  break;
                default:
                  LOGE("from client async_read_some: SOCKS5 ATYP %u not supported", server_data_[3]);
                  boost::asio::async_write(server_socket_, boost::asio::buffer(Socks5::reply_address_type_not_supported, sizeof(Socks5::reply_address_type_not_supported)),
                    [this, self](const boost::system::error_code &write_error_code, std::size_t /*length*/) {
                      if (write_error_code) {
                        std::cerr << "to client async_write: SOCKS5 close failed " << write_error_code.message() << std::endl;
                      }
                    }
                  );
                  return;
              }
              ss_target_address[ss_target_written++] = server_data_[3];
              socks_status_ = Socks5::SOCKS_WAIT_DSTADDR;
              read_from_socks5_client(ss_header_length);
              return;
            } else {
              LOGE("from client async_read_some: SOCKS5 request processing failed");
            }
          }
            return;
          case Socks5::SOCKS_WAIT_DSTADDR: {
            if (ss_target_address[0] == Socks5::SOCKS_ADDR_DOMAIN) {
              socks_status_ = Socks5::SOCKS_WAIT_DOMAIN;
              ss_target_address[ss_target_written++] = server_data_[0];
              read_from_socks5_client(server_data_[0]);
            } else {
              socks_status_ = Socks5::SOCKS_WAIT_DSTPORT;
              memcpy(ss_target_address + ss_target_written, server_data_, length);
              ss_target_written += length;
              read_from_socks5_client(Socks5::SOCKS_LENGTH_PORT);
            }
          }
            return;
          case Socks5::SOCKS_WAIT_DOMAIN: {
            socks_status_ = Socks5::SOCKS_WAIT_DSTPORT;
            memcpy(ss_target_address + ss_target_written, server_data_, length);
            LOGI("Received connection to domain %s", reinterpret_cast<const char *>(server_data_));
            ss_target_written += length;
            read_from_socks5_client(Socks5::SOCKS_LENGTH_PORT);
          }
            return;
          case Socks5::SOCKS_WAIT_DSTPORT: {
            socks_status_ = Socks5::SOCKS_ESTABLISHED;
            memcpy(ss_target_address + ss_target_written, server_data_, length);
            LOGI("Received connection to port %u", htons(*reinterpret_cast<const uint16_t *>(server_data_)));
            ss_target_written += length;

            LOGV("Written %d bytes", ss_target_written);
            for (int i = 0; i < ss_target_written; i++) {
              fprintf(stderr, "0x%02x ", ss_target_address[i]);
            }
            fprintf(stderr, "\n");

            connect_to_ss_server([=] {
              send_to_ss_server(ss_target_address, ss_target_written,
                [this, self]() {
                  boost::asio::async_write(server_socket_,
                    boost::asio::buffer(Socks5::reply_success, sizeof(Socks5::reply_success)),
                    [this, self](const boost::system::error_code &write_error_code, std::size_t /*length*/) {
                      if (write_error_code) {
                        std::cerr << "to client async_write: SOCKS5 close failed "
                                  << write_error_code.message() << std::endl;
                      }
                      LOGI("Session connected to server");
                      // server_socket_.close(); // TODO: remove it.
                      // TODO: set up another function to read user data
                      read_some_from_socks5_client(Shadowsocks::SHADOWSOCKS_AEAD_PAYLOAD_MAX_LENGTH);
                    }
                  );
                }
              );
            });
          }
            return;
          case Socks5::SOCKS_ESTABLISHED:
          default:
            std::cerr << "read_from_socks5_client: unknown status " << socks_status_ << std::endl;
            return;
        }
      }
    );
  }
};

class server {
public:
  server(boost::asio::io_service& io_service, uint16_t listen_port,
         const std::string& server_host, const std::string& server_port)
    : acceptor_(io_service, tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), listen_port)),
      socket_(io_service),
      io_service_(io_service){
    do_accept(server_host, server_port);
  }

private:
  void do_accept(const std::string& server_host, const std::string& server_port) {
    acceptor_.async_accept(socket_,
      [this, server_host, server_port](const boost::system::error_code& ec) {
        if (ec) {
          std::cerr << "Server async_accept: " << ec.message() << std::endl;
        }

        std::make_shared<session>(io_service_, std::move(socket_), server_host, server_port)->start();

        // execute regardless of failed
        do_accept(server_host, server_port);
      });
  }

  std::reference_wrapper<boost::asio::io_service> io_service_;
  tcp::acceptor acceptor_;
  tcp::socket socket_;
};

int main(int argc, char* argv[]) {
  try {
    if (argc != 4) {
      std::cerr << "Usage: " << argv[0] <<" <listen_port> <server_host> <server_port>\n";
      return 1;
    }

    boost::asio::io_service io_service;

    server s(io_service, std::atoi(argv[1]), argv[2], argv[3]);

    LOGI("Listening on port %d", std::atoi(argv[1]));
    io_service.run();
  }
  catch (std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}