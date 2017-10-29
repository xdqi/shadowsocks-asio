cmake_minimum_required(VERSION 3.6)
project(shadowsocks)

if (MSVC)
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11 -Wall -Wextra")
endif()

set(SOURCE_FILES main.cpp crypto.cpp local.cpp)

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.61 REQUIRED COMPONENTS system date_time regex)
find_package(Threads)

if (APPLE)
    set(OPENSSL_ROOT_DIR /usr/local/opt/openssl@1.1)
endif()
if (WIN32)
    add_definitions(-D_WIN32_WINNT=0x0501)
endif()
if (APPLE OR WIN32)
    set(OPENSSL_USE_STATIC_LIBS ON)
    set(sodium_USE_STATIC_LIBS ON)
    add_definitions(-DSODIUM_STATIC)
endif()

find_package(OpenSSL)
include(packaging/Findsodium.cmake)

add_definitions("-DOPENSSL_FOUND=${OPENSSL_FOUND}")
add_definitions("-DSODIUM_FOUND=${sodium_FOUND}")

add_executable(shadowsocks ${SOURCE_FILES})

include_directories(${Boost_INCLUDE_DIRS})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${sodium_INCLUDE_DIR})

target_link_libraries(shadowsocks ${Boost_LIBRARIES})
target_link_libraries(shadowsocks ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries(shadowsocks ${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(shadowsocks debug ${sodium_LIBRARY_DEBUG})
target_link_libraries(shadowsocks optimized ${sodium_LIBRARY_RELEASE})
