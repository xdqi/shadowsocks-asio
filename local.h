#ifndef SHADOWSOCKS_LOCAL_H
#define SHADOWSOCKS_LOCAL_H

#include <boost/asio.hpp>

using boost::asio::ip::tcp;
using boost::asio::ip::udp;



class UdpServer {
public:
  UdpServer(boost::asio::io_service& io_service, TcpSession *session);
  uint16_t listening_port();
  ~UdpServer();

private:
  void read_from_client();
  void read_from_ss_server();
  void send_to_ss_server(const uint8_t *data, size_t length);

  udp::socket server_socket_;
  udp::socket client_socket_;
  udp::endpoint client_endpoint_;
  udp::endpoint server_endpoint_;
  enum { client_max_length = 1024, server_max_length = 1484 };
  uint8_t server_data_[client_max_length];
  uint8_t client_data_[server_max_length];
  TcpSession* session_;
};

#endif //SHADOWSOCKS_LOCAL_H
