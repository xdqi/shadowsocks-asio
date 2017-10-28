#ifndef SHADOWSOCKS_LOCAL_CPP
#define SHADOWSOCKS_LOCAL_CPP

#include "local.h"
#include "crypto.h"
#include <iostream>

inline void UdpServer::read_from_client() {
  server_socket_.async_receive_from(boost::asio::buffer(server_data_, max_length), client_endpoint_,
    [this](boost::system::error_code ec, std::size_t length) {
      if (ec) {
        std::cerr << "UDP Server async_receive_from: " << ec.message() << std::endl;
        return;
      }
      if (server_data_[2]) {  // FRAG != 0
        LOGW("UDP server do not support fragment");
        return;
      }
      send_to_ss_server(server_data_ + 3, length - 3);
    }
  );
}

inline void UdpServer::read_from_ss_server() {
  client_socket_.async_receive_from(boost::asio::buffer(client_data_, max_length), server_endpoint_,
    [this](boost::system::error_code ec, std::size_t length) {
      if (ec) {
        std::cerr << "UDP Client async_receive_from: " << ec.message() << std::endl;
        return;
      }

      Shadowsocks::AeadDecryptor decryptor(session_->cipher_, session_->psk_.data(), client_data_);
      auto message = decryptor.decrypt_packet(client_data_ + session_->cipher_->salt_size_, length - session_->cipher_->salt_size_);

      server_socket_.async_send_to(std::vector<boost::asio::const_buffer>{
                                     boost::asio::buffer(std::vector<uint8_t>{0, 0, 0}),  // 2-byte RSV + 1-byte FRAG
                                     boost::asio::buffer(message)
                                   }, client_endpoint_,
        [this](boost::system::error_code /*ec*/, std::size_t /*bytes_sent*/) {
          read_from_ss_server();
        }
      );
    }
  );
}

inline void UdpServer::send_to_ss_server(const uint8_t *data, size_t length) {
  Shadowsocks::AeadEncryptor encryptor(session_->cipher_, session_->psk_.data());
  auto ciphertext = encryptor.encrypt_packet(data, length);

  client_socket_.async_send_to(std::vector<boost::asio::const_buffer>{
                                 boost::asio::buffer(encryptor.salt(), session_->cipher_->salt_size_),
                                 boost::asio::buffer(ciphertext),
                               }, server_endpoint_,
    [this](boost::system::error_code /*ec*/, std::size_t /*bytes_sent*/) {
      read_from_client();
    }
  );
}

inline TcpSession::~TcpSession() {
  delete udp_server_;
  LOGV("dtor tcp session %p socket %p", this, &server_socket_);
}

inline void TcpSession::start() {
  set_up();
}

inline void TcpSession::set_up() {
  auto self(shared_from_this());
  LOGV("tcp session %p socket %p", this, &server_socket_);

  read_from_socks5_client(Socks5::SOCKS_LENGTH_VERSION_NMETHOD);
}

inline void TcpSession::connect_to_ss_server(const std::function<void ()> &callback) {
  auto self(shared_from_this());
  boost::asio::async_connect(client_socket_, server_addresses_,
    [this, self, callback](const boost::system::error_code& connect_error_code, tcp::resolver::iterator) {
      if (connect_error_code) {
        std::cerr << "to ss-server async_connect: " << connect_error_code.message() << std::endl;
        return;
      }
      LOGV("connected to ss-server");
      read_from_ss_server(cipher_->salt_size_);
      init_connection_with_ss_server(callback);
  });
}

inline void TcpSession::read_from_ss_server(size_t read_len) {
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
            [this, self](const boost::system::error_code& write_error_code, std::size_t /* wrote_len */) {
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

inline void TcpSession::init_connection_with_ss_server(const std::function<void ()> &callback) {
  auto self(shared_from_this());
  encryptor_ = new Shadowsocks::AeadEncryptor(cipher_, psk_.data());

  boost::asio::async_write(client_socket_, boost::asio::buffer(encryptor_->salt(), cipher_->salt_size_),
    [this, self, callback](const boost::system::error_code& write_error_code, std::size_t /* wrote_len */) {
      if (write_error_code) {
        std::cerr << "to server async_write: " << write_error_code.message() << std::endl;
        return;
      }
      callback();
    }
  );
}

inline void TcpSession::send_to_ss_server(const uint8_t *content, size_t length, const std::function<void ()> &callback) {
  auto self(shared_from_this());
  auto ciphertext = encryptor_->encrypt_data(content, length);

  boost::asio::async_write(client_socket_, boost::asio::buffer(ciphertext),
    [this, self, callback](const boost::system::error_code& write_error_code, std::size_t /* wrote_len */) {
      if (write_error_code) {
        std::cerr << "to server async_write: " << write_error_code.message() << std::endl;
        return;
      }
      callback();
    }
  );
}

inline void TcpSession::read_some_from_socks5_client(size_t read_len) {
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

inline void TcpSession::read_from_socks5_client(size_t read_len) {
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
          for (size_t i = 0; i < length; ++i) {
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
              return;
            }

            socks_command_ = (Socks5::command) server_data_[1];  // set socks command to connect

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
            LOGI("UDP request received");
            socks_status_ = Socks5::SOCKS_WAIT_UDP_CLOSE;
            udp_server_ = new UdpServer(io_service_, this);

            uint16_t port = htons(udp_server_->listening_port());
            uint8_t response[sizeof(Socks5::reply_success) + Socks5::SOCKS_LENGTH_ADDR_IPV6 - Socks5::SOCKS_LENGTH_ADDR_IPV4];
            size_t response_size = sizeof(Socks5::reply_success);
            memcpy(response, Socks5::reply_success, sizeof(Socks5::reply_success));

            const auto &endpoint = server_socket_.local_endpoint();
            const auto &address = endpoint.address();
            if (address.is_v4()) {  // IPv4 server got IPv4 address
              response[3] = Socks5::SOCKS_ADDR_IPV4;
              memcpy(response + 4, address.to_v4().to_bytes().data(), Socks5::SOCKS_LENGTH_ADDR_IPV4);
              memcpy(response + 4 + Socks5::SOCKS_LENGTH_ADDR_IPV4, &port, Socks5::SOCKS_LENGTH_PORT);
            } else if (address.is_v6() && (address.to_v6().is_v4_mapped() || address.to_v6().is_v4_compatible())) {
              // IPv6 server got IPv4-mapped address
              response[3] = Socks5::SOCKS_ADDR_IPV4;
              memcpy(response + 4, address.to_v6().to_v4().to_bytes().data(), Socks5::SOCKS_LENGTH_ADDR_IPV4);
              memcpy(response + 4 + Socks5::SOCKS_LENGTH_ADDR_IPV4, &port, Socks5::SOCKS_LENGTH_PORT);
            } else {  // IPv6 server got IPv6 address
              response[3] = Socks5::SOCKS_ADDR_IPV6;
              memcpy(response + 4, address.to_v6().to_bytes().data(), Socks5::SOCKS_LENGTH_ADDR_IPV6);
              memcpy(response + 4 + Socks5::SOCKS_LENGTH_ADDR_IPV6, &port, Socks5::SOCKS_LENGTH_PORT);
              response_size += Socks5::SOCKS_LENGTH_ADDR_IPV6 - Socks5::SOCKS_LENGTH_ADDR_IPV4;
            }

            boost::asio::async_write(server_socket_,
              boost::asio::buffer(response, response_size),
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

          LOGI("TCP request received");
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

#endif