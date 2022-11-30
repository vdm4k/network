#pragma once
#include <socket_proxy/linux/linux_stream_socket_factory.h>

namespace jkl::sp::lnx {

stream_socket_factory::~stream_socket_factory() {}

stream_socket_ptr stream_socket_factory::init_connection(
    proto::ip_addr const& peer_address) {
  return nullptr;
}

stream_socket_ptr create_listener(proto::ip_addr const& self_address,
                                  in_conn_handler_t in_conn_fun_t,
                                  in_conn_user_data_t user_data) {
  return nullptr;
}

}  // namespace jkl::sp::lnx
