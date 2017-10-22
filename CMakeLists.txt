cmake_minimum_required(VERSION 3.6)
project(shadowsocks)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11")

set(SOURCE_FILES main.cpp crypto.cpp)

set(Boost_USE_STATIC_LIBS ON)
find_package(Boost 1.61 REQUIRED COMPONENTS system)
find_package(Threads)

add_executable(shadowsocks ${SOURCE_FILES})

target_link_libraries(shadowsocks ${Boost_LIBRARIES})
target_link_libraries(shadowsocks ${CMAKE_THREAD_LIBS_INIT})
