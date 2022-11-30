#pragma once
#include <socket_proxy/linux/linux_stream_socket.h>

namespace jkl::sp::lnx {

stream_socket::~stream_socket() {}

stream_socket::send_result stream_socket::send(void *data, size_t size) {}

stream_socket::receive_result stream_socket::receive(uint8_t *data,
                                                     size_t size) {}

jkl::proto::ip_addr const &stream_socket::get_self_address() const {}

jkl::proto::ip_addr const &stream_socket::get_peer_address() const {}

std::string const &stream_socket::get_detailed_error() const { return _error; }

stream_socket::connection_state stream_socket::get_state() const {}

stream_socket::stream_type stream_socket::get_type() const {}

void stream_socket::set_received_data_cb(received_data_cb cb, void *first_param,
                                         void *second_param) {
  _received_data_cb = cb;
  _f_param_rec_cb = first_param;
  _s_param_rec_cb = second_param;
}

void stream_socket::set_send_data_cb(send_data_cb cb, void *first_param,
                                     void *second_param) {
  _send_data_cb = cb;
  _f_param_send_cb = first_param;
  _s_param_send_cb = second_param;
}

void stream_socket::set_state_changed_cb(state_changed_cb cb, void *first_param,
                                         void *second_param) {
  _state_changed_cb = cb;
  _f_param_sc_cb = first_param;
  _s_param_sc_cb = second_param;
}

}  // namespace jkl::sp::lnx
