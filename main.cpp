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
#include "local.h"

using boost::asio::ip::tcp;
using boost::asio::ip::udp;

class TcpServer {
public:
  TcpServer(boost::asio::io_service& io_service, uint16_t listen_port,
            const std::string& server_host, const std::string& server_port,
            const std::string &cipher, const std::string &password)
    : io_service_(io_service),
      acceptor_(io_service, tcp::endpoint(boost::asio::ip::address::from_string("127.0.0.1"), listen_port)),
      socket_(io_service),
      server_host_(server_host),
      server_port_(server_port),
      cipher_(Shadowsocks::AeadCipher::get_cipher(cipher)),
      psk_(password_to_key((const uint8_t *) password.c_str(), password.length(), cipher_->key_size_)) {
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