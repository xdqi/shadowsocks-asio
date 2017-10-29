// #define BOOST_ASIO_ENABLE_HANDLER_TRACKING

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
            const tcp::resolver::iterator &server_addresses,
            const Shadowsocks::AeadCipher *cipher, const std::string &password)
    : io_service_(io_service),
      acceptor_(io_service, tcp::endpoint(boost::asio::ip::address_v6::any(), listen_port)),
      socket_(io_service),
      server_addresses_(server_addresses),
      cipher_(cipher),
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

        std::make_shared<TcpSession>(io_service_, std::move(socket_), server_addresses_, cipher_, psk_)->start();

        // execute regardless of failed
        do_accept();
      });
  }

  std::reference_wrapper<boost::asio::io_service> io_service_;
  tcp::acceptor acceptor_;
  tcp::socket socket_;
  tcp::resolver::iterator server_addresses_;
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

    LOGI("Resolving server address ...");
    boost::system::error_code resolve_error;
    tcp::resolver resolver(io_service);
    tcp::resolver::query query(argv[2], argv[3]);
    auto server_addresses = resolver.resolve(query, resolve_error);
    if (resolve_error) {
      LOGE("Unable to resolve ss server addresses %s:%s", argv[2], argv[3]);
      exit(-1);
    }

    auto cipher = Shadowsocks::AeadCipher::get_cipher(argv[4]);
    if (!cipher) {
      LOGE("Invalid cipher name %s", argv[4]);
      exit(-1);
    }

    TcpServer s(io_service, std::atoi(argv[1]), server_addresses, cipher, argv[5]);

    LOGI("Listening on port %d", std::atoi(argv[1]));
    io_service.run();
  }
  catch (std::exception& e) {
    std::cerr << "Exception: " << e.what() << "\n";
  }

  return 0;
}