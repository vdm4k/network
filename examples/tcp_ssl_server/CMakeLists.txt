cmake_minimum_required(VERSION 3.3.2)
project(tcp_ssl_server)

add_executable(${PROJECT_NAME} main.cpp )

target_link_libraries(${PROJECT_NAME} PUBLIC Threads::Threads network CLI11::CLI11 ${ADDITIONAL_DEPS})
