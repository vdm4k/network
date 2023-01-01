#pragma once
#include <socket_proxy/linux/stream_factory.h>

namespace jkl::sp::lnx {

stream_factory::~stream_factory() {}

stream_ptr stream_factory::create_send_stream(
    proto::ip_addr const& peer_address) {
  return nullptr;
}

stream_ptr stream_factory::create_listen_stream(
    proto::ip_addr const& self_address, in_conn_handler_cb in_conn_fun_t,
    in_conn_handler_data_cb user_data) {
  return nullptr;
}

}  // namespace jkl::sp::lnx
