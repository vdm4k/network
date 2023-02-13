cmake_minimum_required(VERSION 3.3.2)
project(socket_proxy_apps VERSION 0.0.2 DESCRIPTION "socket proxy apps" LANGUAGES CXX)

include("${PROJECT_SOURCE_DIR}/third_party/cli11.cmake")
add_subdirectory(tcp_client)
add_subdirectory(tcp_server)

