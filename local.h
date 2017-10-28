#ifndef SHADOWSOCKS_LOCAL_H
#define SHADOWSOCKS_LOCAL_H

#include "crypto.h"
#include <boost/asio.hpp>

using boost::asio::ip::tcp;
using boost::asio::ip::udp;

class UdpServer;

class TcpSession : public std::enable_shared_from_this<TcpSession> {
  friend class UdpServer;

public:
  TcpSession(boost::asio::io_service &io_service, tcp::socket socket,
             const std::string &server_host, const std::string &server_port,
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
      udp_server_(nullptr) {
  }

  void start();

  ~TcpSession();

private:

  void set_up();

  void connect_to_ss_server(const std::function<void()> &callback);

  void read_from_ss_server(size_t read_len);

  void init_connection_with_ss_server(const std::function<void()> &callback);

  void send_to_ss_server(const uint8_t *content, size_t length, const std::function<void()> &callback);

  void read_some_from_socks5_client(size_t read_len);

  void read_from_socks5_client(size_t read_len);

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

  const Shadowsocks::AeadCipher *cipher_;
  std::vector<uint8_t> psk_;
  Shadowsocks::AeadEncryptor *encryptor_;
  Shadowsocks::AeadDecryptor *decryptor_;
  UdpServer *udp_server_;

};

class UdpServer {
public:
  UdpServer(boost::asio::io_service &io_service, TcpSession *session) :
    server_socket_(io_service, udp::endpoint(udp::v4(), 0)),
    client_socket_(io_service, udp::endpoint(udp::v4(), 0)),
    server_endpoint_(boost::asio::ip::address::from_string("127.0.0.1"), 23333),
    session_(session) {
    LOGI("UDP server %p created", this);
    read_from_client();
    read_from_ss_server();
  }

  uint16_t listening_port() {
    return server_socket_.local_endpoint().port();
  }

  ~UdpServer() {
    LOGI("UDP server %p destroyed", this);
    server_socket_.close();  // cancel all operations and stop server
    client_socket_.close();
  }

private:
  void read_from_client();

  void read_from_ss_server();

  void send_to_ss_server(const uint8_t *data, size_t length);

  udp::socket server_socket_;
  udp::socket client_socket_;
  udp::endpoint client_endpoint_;
  udp::endpoint server_endpoint_;
  enum {
    client_max_length = 1024, server_max_length = 1484
  };
  uint8_t server_data_[client_max_length];
  uint8_t client_data_[server_max_length];
  TcpSession *session_;
};

#include "local.cpp" // have to include implementation, wtf

#endif //SHADOWSOCKS_LOCAL_H
