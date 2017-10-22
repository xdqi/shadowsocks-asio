cmake_minimum_required(VERSION 3.6)
project(shadowsocks)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

set(SOURCE_FILES main.cpp crypto.cpp)

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.61 REQUIRED COMPONENTS system)
find_package(Threads)

if(APPLE)
    set(OPENSSL_ROOT_DIR /usr/local/opt/openssl@1.1)
endif()
find_package(OpenSSL)

add_executable(shadowsocks ${SOURCE_FILES})

include_directories(${OPENSSL_INCLUDE_DIR})
target_link_libraries(shadowsocks ${Boost_LIBRARIES})
target_link_libraries(shadowsocks ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(shadowsocks ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(shadowsocks sodium)