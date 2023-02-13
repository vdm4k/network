cmake_minimum_required(VERSION 3.3.2)
project(tcp_server)

add_executable(${PROJECT_NAME} main.cpp )

find_package(OpenSSL)

target_link_libraries(${PROJECT_NAME} PUBLIC Threads::Threads socket_proxy::socket_proxy CLI11::CLI11)
