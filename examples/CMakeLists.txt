cmake_minimum_required(VERSION 3.3.2)
project(network_examples VERSION 0.9.0 DESCRIPTION "socket proxy apps" LANGUAGES CXX)

include("${PROJECT_SOURCE_DIR}/third_party/cli11.cmake")
add_subdirectory(tcp_client)
add_subdirectory(udp_client)
add_subdirectory(tcp_server)
if(WITH_TCP_SSL)
    add_subdirectory(tcp_ssl_client)
    add_subdirectory(tcp_ssl_server)
endif() # WITH_TCP_SSL
if(WITH_SCTP)
    add_subdirectory(sctp_client)
    add_subdirectory(sctp_server)
endif() # WITH_SCTP
if(WITH_SCTP_SSL)
    add_subdirectory(sctp_ssl_client)
    add_subdirectory(sctp_ssl_server)
endif() # WITH_SCTP_SSL
if(WITH_UDP_SSL)
    add_subdirectory(udp_ssl_client)
    add_subdirectory(udp_ssl_server)
endif() # WITH_UDP_SSL

