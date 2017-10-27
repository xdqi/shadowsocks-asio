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
using boost::asio::ip::udp;


class TcpSession : public std::enable_shared_from_this<TcpSession> {
  friend class UdpServer;

public:
  TcpSession(boost::asio::io_service& io_service, tcp::socket socket,
             const std::string& server_host, const std::string& server_port,
             const Shadowsocks::AeadCipher *cipher, const std::vector<uint8_t> &psk)
    : io_service_(io_service),
      server_socket_(std::move(socket)),
      client_socket_(io_service),
      resolver_(io_service),
      query_(server_host, server_port),
      socks_status_(Socks5::SOCKS_NEW),
      shadowsocks_status_(Shadowsocks::SHADOWSOCKS_NEW),
      server_data_{0},
      client_data_{0},
      ss_target_address{0},
      cipher_(cipher),
      psk_(psk),
      udp_server_(nullptr)
  {
  }

  void start() {
    set_up();
  }

  ~TcpSession() {
    if (udp_server_) {
      delete udp_server_;
    }
    LOGV("dtor tcp session %p socket %p", this, &server_socket_);
  }

private:
  std::reference_wrapper<boost::asio::io_service> io_service_;

  tcp::socket server_socket_;
  tcp::socket client_socket_;

  tcp::resolver resolver_;
  tcp::resolver::query query_;

  enum Socks5::status socks_status_;
  enum Socks5::command socks_command_;
  enum Shadowsocks::status shadowsocks_status_;

  uint8_t server_data_[Shadowsocks::SHADOWSOCKS_AEAD_PAYLOAD_MAX_LENGTH];
  uint8_t client_data_[Shadowsocks::SHADOWSOCKS_AEAD_PAYLOAD_MAX_LENGTH];
  uint8_t ss_target_address[Shadowsocks::SHADOWSOCKS_HEADER_MAX_LENGTH];
  int ss_target_written = 0;

  std::vector<uint8_t> psk_;
  const Shadowsocks::AeadCipher *cipher_;
  Shadowsocks::AeadEncryptor *encryptor_;
  Shadowsocks::AeadDecryptor *decryptor_;
  UdpServer *udp_server_;


  void set_up() {
    auto self(shared_from_this());
    LOGV("tcp session %p socket %p", this, &server_socket_);

    read_from_socks5_client(Socks5::SOCKS_LENGTH_VERSION_NMETHOD);
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
            //hexdump(data.data(), payload_length);
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
        //hexdump(server_data_, length);
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
            if (server_data_[0] == Socks5::SOCKS_VERSION_5) { // SOCKS 5
              socks_status_ = Socks5::SOCKS_WAIT_METHODS;
              read_from_socks5_client(server_data_[1]);  // read methods from NMETHOD field
            } else if (server_data_[0] == Socks5::SOCKS_VERSION_4) { // SOCKS 4 or SOCKS 4a
              if (server_data_[1] == Socks5::SOCKS_CONNECT) {
                // parse port and ip
                socks_status_ = Socks5::SOCKS4_WAIT_DSTPORT_IP;
                read_from_socks5_client(Socks5::SOCKS4_LENGTH_DSTPORT_IP);
              } else {
                LOGE("from client async_read: SOCKS4 CMD %u not supported", server_data_[1]);
                boost::asio::async_write(server_socket_, boost::asio::buffer(Socks5::socks4_rejected, sizeof(Socks5::socks4_rejected)),
                  [this, self](const boost::system::error_code &write_error_code, std::size_t /*length*/) {
                    if (write_error_code) {
                      std::cerr << "to client async_write: SOCKS4 close failed " << write_error_code.message() << std::endl;
                    }
                  }
                );
              }
            } else {
              LOGE("from client async_read: SOCKS5 version error");
              hexdump(server_data_, length);
            }
          }
            return;
          case Socks5::SOCKS_WAIT_METHODS: {
            bool have_method = false;
            for (int i = 0; i < length; ++i) {
              if (server_data_[i] == Socks5::SOCKS_AUTH_NO) {
                have_method = true;
                break;
              }
            }
            if (have_method) {
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
              LOGE("from client async_read: SOCKS5 methods not supported");
              hexdump(server_data_, length);
            }
          }
            return;
          case Socks5::SOCKS4_WAIT_DSTPORT_IP: {
            // When using SOCKS4, we set ss_target_address as following format
            // [2-byte port][1-byte type][variable-length host][2-byte port]
            // Then we send ss_target_address+2 to server
            memcpy(ss_target_address, server_data_, Socks5::SOCKS_LENGTH_PORT);
            ss_target_written += Socks5::SOCKS_LENGTH_PORT;
            // We'll determine if it's domain later. So we believe it's IPv4 address here :)
            ss_target_address[ss_target_written++] = Socks5::SOCKS_ADDR_IPV4;
            memcpy(ss_target_address + ss_target_written,
                   server_data_ + Socks5::SOCKS_LENGTH_PORT,
                   Socks5::SOCKS_LENGTH_ADDR_IPV4);
            ss_target_written += Socks5::SOCKS_LENGTH_ADDR_IPV4;
            socks_status_ = Socks5::SOCKS4_WAIT_USERID;
            read_from_socks5_client(1);
          }
            return;
          case Socks5::SOCKS4_WAIT_USERID: {
            // iterate until NUL
            if (server_data_[0] == 0) {
              if (ss_target_address[3] == 0 &&
                  ss_target_address[4] == 0 &&
                  ss_target_address[5] == 0 &&
                  ss_target_address[6] != 0) {  // determine SOCKS 4a
                ss_target_address[2] = Socks5::SOCKS_ADDR_DOMAIN;
                socks_status_ = Socks5::SOCKS4_WAIT_DOMAIN;
                ss_target_written -= Socks5::SOCKS_LENGTH_ADDR_IPV4;  // remove fake IPv4 address from buffer
                ss_target_written++;  // but reserve the vary length byte
                read_from_socks5_client(1);
              } else {
                socks_status_ = Socks5::SOCKS_ESTABLISHED;
                memcpy(ss_target_address + ss_target_written, ss_target_address, Socks5::SOCKS_LENGTH_PORT);
                connect_to_ss_server([=] {
                  hexdump(ss_target_address + Socks5::SOCKS_LENGTH_PORT, ss_target_written);
                  send_to_ss_server(ss_target_address + Socks5::SOCKS_LENGTH_PORT, ss_target_written,
                    [this, self]() {
                      boost::asio::async_write(server_socket_,
                                               boost::asio::buffer(Socks5::socks4_server_hello, sizeof(Socks5::socks4_server_hello)),
                        [this, self](const boost::system::error_code &write_error_code, std::size_t /*length*/) {
                          if (write_error_code) {
                            std::cerr << "to client async_write: SOCKS4 close failed "
                                      << write_error_code.message() << std::endl;
                          }
                          LOGI("Session connected to SOCKS4 server");
                          read_some_from_socks5_client(Shadowsocks::SHADOWSOCKS_AEAD_PAYLOAD_MAX_LENGTH);
                        }
                      );
                    }
                  );
                });
              }
            } else {
              // We do not care the user id, just ignore it
              read_from_socks5_client(1);
            }
          }
            return;
          case Socks5::SOCKS4_WAIT_DOMAIN: {
            // iterate until NUL
            if (server_data_[0] == 0) {
              socks_status_ = Socks5::SOCKS_ESTABLISHED;

              memcpy(ss_target_address + ss_target_written, ss_target_address, Socks5::SOCKS_LENGTH_PORT);
              connect_to_ss_server([=] {
                hexdump(ss_target_address + Socks5::SOCKS_LENGTH_PORT, ss_target_written);
                send_to_ss_server(ss_target_address + Socks5::SOCKS_LENGTH_PORT, ss_target_written,
                  [this, self]() {
                    boost::asio::async_write(server_socket_,
                                             boost::asio::buffer(Socks5::socks4_server_hello,
                                                                 sizeof(Socks5::socks4_server_hello)),
                      [this, self](const boost::system::error_code &write_error_code, std::size_t /*length*/) {
                        if (write_error_code) {
                          std::cerr << "to client async_write: SOCKS4a close failed "
                                    << write_error_code.message() << std::endl;
                        }
                        LOGI("Session connected to SOCKS4a server");
                        read_some_from_socks5_client(Shadowsocks::SHADOWSOCKS_AEAD_PAYLOAD_MAX_LENGTH);
                      }
                    );
                  }
                );
              });
            } else {
              ss_target_address[ss_target_written++] = server_data_[0];
              ss_target_address[3]++;
              read_from_socks5_client(1);
            }
          }
            return;
          case Socks5::SOCKS_WAIT_REQUEST: {
            if (server_data_[0] == Socks5::SOCKS_VERSION_5) {
              if (server_data_[1] != Socks5::SOCKS_CONNECT && server_data_[1] != Socks5::SOCKS_UDP_ASSOCIATE) {
                LOGE("from client async_read: SOCKS5 CMD %u not supported", server_data_[1]);
                boost::asio::async_write(server_socket_, boost::asio::buffer(Socks5::reply_command_not_supported, sizeof(Socks5::reply_command_not_supported)),
                  [this, self](const boost::system::error_code &write_error_code, std::size_t /*length*/) {
                    if (write_error_code) {
                      std::cerr << "to client async_write: SOCKS5 close failed " << write_error_code.message() << std::endl;
                    }
                  }
                );
                socks_command_ = (Socks5::command) server_data_[1];
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
                  LOGE("from client async_read: SOCKS5 ATYP %u not supported", server_data_[3]);
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
            memcpy(ss_target_address + ss_target_written, server_data_, length);
            LOGI("Received connection to port %u", htons(*reinterpret_cast<const uint16_t *>(server_data_)));
            ss_target_written += length;

            LOGV("ss target address %d bytes: ", ss_target_written);
            hexdump(ss_target_address, ss_target_written);

            if (socks_command_ == Socks5::SOCKS_UDP_ASSOCIATE) {
              socks_status_ = Socks5::SOCKS_WAIT_UDP_CLOSE;
              udp_server_ = new UdpServer(io_service_, this);

              uint16_t port = htons(udp_server_->listening_port());
              uint8_t response[sizeof(Socks5::reply_success)];
              memcpy(response, Socks5::reply_success, sizeof(Socks5::reply_success));
              memcpy(response + 4, "\x7f\x00\x00\x01", Socks5::SOCKS_LENGTH_ADDR_IPV4);
              memcpy(response + 8, &port, Socks5::SOCKS_LENGTH_PORT);

              boost::asio::async_write(server_socket_,
                boost::asio::buffer(response, sizeof(response)),
                  [this, self](const boost::system::error_code &write_error_code, std::size_t /*length*/) {
                    if (write_error_code) {
                      std::cerr << "to client async_write: SOCKS5 reply failed "
                                << write_error_code.message() << std::endl;
                    }
                    LOGI("UDP Association established to SOCKS5 server");
                    read_from_socks5_client(1);
                  }
              );
              return;
            }

            socks_status_ = Socks5::SOCKS_ESTABLISHED;

            connect_to_ss_server([=] {
              send_to_ss_server(ss_target_address, ss_target_written,
                [this, self]() {
                  boost::asio::async_write(server_socket_,
                    boost::asio::buffer(Socks5::reply_success, sizeof(Socks5::reply_success)),
                    [this, self](const boost::system::error_code &write_error_code, std::size_t /*length*/) {
                      if (write_error_code) {
                        std::cerr << "to client async_write: SOCKS5 reply failed "
                                  << write_error_code.message() << std::endl;
                      }
                      LOGI("Session connected to SOCKS5 server");
                      read_some_from_socks5_client(Shadowsocks::SHADOWSOCKS_AEAD_PAYLOAD_MAX_LENGTH);
                    }
                  );
                }
              );
            });
          }
            return;
          case Socks5::SOCKS_WAIT_UDP_CLOSE:
            LOGI("UDP Association closed by client");  // never reached
            break;
          case Socks5::SOCKS_ESTABLISHED:
          default:
            std::cerr << "read_from_socks5_client: unknown status " << socks_status_ << std::endl;
            return;
        }
      }
    );
  }
};

class TcpServer {
public:
  TcpServer(boost::asio::io_service& io_service, uint16_t listen_port,
            const std::string& server_host, const std::string& server_port,
            const std::string &cipher, const std::string &password)
    : acceptor_(io_service, tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), listen_port)),
      socket_(io_service),
      io_service_(io_service),
      cipher_(Shadowsocks::AeadCipher::get_cipher(cipher)),
      psk_(password_to_key((const uint8_t *) password.c_str(), password.length(), cipher_->key_size_)),
      server_host_(server_host),
      server_port_(server_port) {
      do_accept();
  }

private:
  void do_accept() {
    acceptor_.async_accept(socket_,
      [this](const boost::system::error_code& ec) {
        if (ec) {
          std::cerr << "Server async_accept: " << ec.message() << std::endl;
        }

        std::make_shared<TcpSession>(io_service_, std::move(socket_), server_host_, server_port_, cipher_, psk_)->start();

        // execute regardless of failed
        do_accept();
      });
  }

  std::reference_wrapper<boost::asio::io_service> io_service_;
  tcp::acceptor acceptor_;
  tcp::socket socket_;
  std::string server_host_;
  std::string server_port_;
  const Shadowsocks::AeadCipher *cipher_;
  std::vector<uint8_t> psk_;
};

class UdpServer {
public:
  UdpServer(boost::asio::io_service& io_service, TcpSession *session)
    : server_socket_(io_service, udp::endpoint(udp::v4(), 0)),
      client_socket_(io_service, udp::endpoint(udp::v4(), 0)),
      server_endpoint_(boost::asio::ip::address::from_string("127.0.0.1"), 23333),
      session_(session) {
    read_from_client();
    read_from_ss_server();
  }

  ~UdpServer() {
    server_socket_.close();  // cancel all operations and stop server
    client_socket_.close();
  }

  uint16_t listening_port() {
    return server_socket_.local_endpoint().port();
  }

private:
  void read_from_client() {
    server_socket_.async_receive_from(boost::asio::buffer(server_data_, client_max_length), client_endpoint_,
      [this](boost::system::error_code ec, std::size_t length) {
        if (ec) {
          std::cerr << "UDP Server async_receive_from: " << ec.message() << std::endl;
        }
        send_to_ss_server(server_data_ + 3, length - 3);
      }
    );
  }

  void read_from_ss_server() {
    client_socket_.async_receive_from(boost::asio::buffer(client_data_, server_max_length), server_endpoint_,
    [this](boost::system::error_code ec, std::size_t length) {
        if (ec) {
          std::cerr << "UDP Client async_receive_from: " << ec.message() << std::endl;
        }

        Shadowsocks::AeadDecryptor decryptor(session_->cipher_, session_->psk_.data(), client_data_);
        auto message = decryptor.decrypt_packet(client_data_ + session_->cipher_->salt_size_, length - session_->cipher_->salt_size_);

      server_socket_.async_send_to(boost::asio::buffer(message), client_endpoint_,
          [this](boost::system::error_code /*ec*/, std::size_t /*bytes_sent*/) {
            read_from_ss_server();
          }
        );
      }
    );
  }

  void send_to_ss_server(const uint8_t *data, size_t length) {
    Shadowsocks::AeadEncryptor encryptor(session_->cipher_, session_->psk_.data());
    auto ciphertext = encryptor.encrypt_packet(data, length);

    client_socket_.async_send_to(boost::asio::buffer(ciphertext), server_endpoint_,
      [this](boost::system::error_code /*ec*/, std::size_t /*bytes_sent*/) {
        read_from_client();
      }
    );
  }

  udp::socket server_socket_;
  udp::socket client_socket_;
  udp::endpoint client_endpoint_;
  udp::endpoint server_endpoint_;
  enum { client_max_length = 1024, server_max_length = 1484 };
  uint8_t server_data_[client_max_length];
  uint8_t client_data_[server_max_length];
  TcpSession* session_;
};

int main(int argc, char* argv[]) {
  try {
    if (argc != 6) {
      printf("Shadowsocks ASIO prototype.\n\n");
      Shadowsocks::print_all_ciphers();
      printf("\nUsage: %s <listen_port> <server_host> <server_port> <cipher> <password>\n", argv[0]);
      return 1;
    }

    boost::asio::io_service io_service;

    TcpServer s(io_service, std::atoi(argv[1]), argv[2], argv[3], argv[4], argv[5]);

    LOGI("Listening on port %d", std::atoi(argv[1]));
    io_service.run();
  }
  catch (std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}