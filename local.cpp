#include "local.h"

UdpServer::UdpServer(boost::asio::io_service& io_service, TcpSession *session)
: server_socket_(io_service, udp::endpoint(udp::v4(), 0)),
client_socket_(io_service, udp::endpoint(udp::v4(), 0)),
server_endpoint_(boost::asio::ip::address::from_string("127.0.0.1"), 23333),
session_(session) {
  read_from_client();
  read_from_ss_server();
}

UdpServer::~UdpServer() {
  server_socket_.close();  // cancel all operations and stop server
  client_socket_.close();
}

UdpServer::uint16_t listening_port() {
  return server_socket_.local_endpoint().port();
}


void UdpServer::read_from_client() {
  server_socket_.async_receive_from(boost::asio::buffer(server_data_, client_max_length), client_endpoint_,
                                    [this](boost::system::error_code ec, std::size_t length) {
                                      if (ec) {
                                        std::cerr << "UDP Server async_receive_from: " << ec.message() << std::endl;
                                      }
                                      send_to_ss_server(server_data_ + 3, length - 3);
                                    }
  );
}

void UdpServer::read_from_ss_server() {
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

void UdpServer::send_to_ss_server(const uint8_t *data, size_t length) {
  Shadowsocks::AeadEncryptor encryptor(session_->cipher_, session_->psk_.data());
  auto ciphertext = encryptor.encrypt_packet(data, length);

  client_socket_.async_send_to(boost::asio::buffer(ciphertext), server_endpoint_,
                               [this](boost::system::error_code /*ec*/, std::size_t /*bytes_sent*/) {
                                 read_from_client();
                               }
  );
}