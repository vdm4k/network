cmake_minimum_required(VERSION 3.3.2)
project(network_apps VERSION 0.0.2 DESCRIPTION "socket proxy apps" LANGUAGES CXX)

include("${PROJECT_SOURCE_DIR}/third_party/cli11.cmake")
add_subdirectory(tcp_client)
add_subdirectory(tcp_server)
if(WITH_SSL)
    add_subdirectory(tcp_ssl_client)
    add_subdirectory(tcp_ssl_server)
endif()

