#define BOOST_ASIO_ENABLE_HANDLER_TRACKING

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
enum version {
  SOCKS_VERSION_4 = 4,
  SOCKS_VERSION_5 = 5
};

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

class session : public std::enable_shared_from_this<session> {
public:
  session(boost::asio::io_service& io_service, tcp::socket socket,
          const std::string& server_host, const std::string& server_port,
          const Shadowsocks::AeadCipher *cipher, const std::vector<uint8_t> &psk)
    : server_socket_(std::move(socket)),
      client_socket_(io_service),
      resolver_(io_service),
      query_(server_host, server_port),
      socks_status_(Socks5::SOCKS_NEW),
      shadowsocks_status_(Shadowsocks::SHADOWSOCKS_NEW),
      server_data_{0},
      client_data_{0},
      ss_target_address{0},
      cipher_(cipher),
      psk_(psk)
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
  int ss_target_written = 0;

  std::vector<uint8_t> psk_;
  const Shadowsocks::AeadCipher *cipher_;
  Shadowsocks::AeadEncryptor *encryptor_;
  Shadowsocks::AeadDecryptor *decryptor_;


  void set_up() {
    auto self(shared_from_this());
    LOGV("session %p socket %p\n", this, &server_socket_);

    read_from_socks5_client(Socks5::SOCKS_LENGTH_CLIENT_HELLO);
  }

  void connect_to_ss_server(const std::function<void ()> &callback) {
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
            read_from_ss_server(cipher_->salt_size_);
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

            decryptor_ = new Shadowsocks::AeadDecryptor(cipher_, psk_.data(), client_data_);
            shadowsocks_status_ = Shadowsocks::SHADOWSOCKS_WAIT_LENGTH;
            read_from_ss_server(Shadowsocks::SHADOWSOCKS_AEAD_LENGTH_LENGTH + cipher_->tag_size_);
          }
            return;
          case Shadowsocks::SHADOWSOCKS_WAIT_LENGTH: {
            auto length_net = decryptor_->decrypt_data(client_data_, length);
            uint16_t payload_length = htons(*reinterpret_cast<const uint16_t *>(length_net.data()));
            LOGV("read_from_ss_server payload length: %u", payload_length);
            shadowsocks_status_ = Shadowsocks::SHADOWSOCKS_WAIT_PAYLOAD;
            read_from_ss_server(payload_length + cipher_->tag_size_);
          }
            return;
          case Shadowsocks::SHADOWSOCKS_WAIT_PAYLOAD: {
            auto data = decryptor_->decrypt_data(client_data_, length);
            unsigned long long payload_length = length - cipher_->tag_size_;
            LOGV("read_from_ss_server payload %llu bytes: ", payload_length);
            hexdump(data.data(), payload_length);
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
    encryptor_ = new Shadowsocks::AeadEncryptor(cipher_, psk_.data());

    boost::asio::async_write(client_socket_, boost::asio::buffer(encryptor_->salt(), cipher_->salt_size_),
      [this, self, callback](const boost::system::error_code& write_error_code, std::size_t wrote_len) {
        if (write_error_code) {
          std::cerr << "to server async_write: " << write_error_code.message() << std::endl;
          return;
        }
        callback();
      }
    );
  }

  void send_to_ss_server(const uint8_t *content, size_t length, const std::function<void ()> &callback) {
    auto self(shared_from_this());
    auto ciphertext = encryptor_->encrypt_data(content, length);

    boost::asio::async_write(client_socket_, boost::asio::buffer(ciphertext),
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
            if (server_data_[0] == Socks5::SOCKS_VERSION_5) {
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

            LOGV("ss target address %d bytes: ", ss_target_written);
            hexdump(ss_target_address, ss_target_written);

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
         const std::string& server_host, const std::string& server_port,
         const std::string &cipher, const std::string &password)
    : acceptor_(io_service, tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), listen_port)),
      socket_(io_service),
      io_service_(io_service),
      cipher_(Shadowsocks::AeadCipher::get_cipher(cipher)),
      psk_(password_to_key((const uint8_t *) password.c_str(), password.length(), cipher_->key_size_)) {
    do_accept(server_host, server_port);
  }

private:
  void do_accept(const std::string& server_host, const std::string& server_port) {
    acceptor_.async_accept(socket_,
      [this, server_host, server_port](const boost::system::error_code& ec) {
        if (ec) {
          std::cerr << "Server async_accept: " << ec.message() << std::endl;
        }

        std::make_shared<session>(io_service_, std::move(socket_), server_host, server_port, cipher_, psk_)->start();

        // execute regardless of failed
        do_accept(server_host, server_port);
      });
  }

  std::reference_wrapper<boost::asio::io_service> io_service_;
  tcp::acceptor acceptor_;
  tcp::socket socket_;
  const Shadowsocks::AeadCipher *cipher_;
  std::vector<uint8_t> psk_;
};

int main(int argc, char* argv[]) {
  try {
    if (argc != 6) {
      std::cerr << "Usage: " << argv[0] <<" <listen_port> <server_host> <server_port> <cipher> <password>\n";
      return 1;
    }

    boost::asio::io_service io_service;

    server s(io_service, std::atoi(argv[1]), argv[2], argv[3], argv[4], argv[5]);

    LOGI("Listening on port %d", std::atoi(argv[1]));
    io_service.run();
  }
  catch (std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}