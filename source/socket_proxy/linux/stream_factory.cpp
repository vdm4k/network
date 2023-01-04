#include <socket_proxy/linux/stream_factory.h>
#include <socket_proxy/linux/tcp_listen_stream.h>
#include <socket_proxy/linux/tcp_send_stream.h>
#include <socket_proxy/linux/tcp_settings.h>

namespace jkl::sp::lnx {
ev_stream_factory::ev_stream_factory() noexcept : _ev_loop{ev::init()} {}

ev_stream_factory::~ev_stream_factory() { ev::clean_up(_ev_loop); }

stream_ptr ev_stream_factory::create_stream(stream_settings* stream_set) {
  if (auto* param = dynamic_cast<send_stream_socket_parameters*>(stream_set);
      param) {
    auto sck = std::make_unique<tcp_send_stream>();
    sck->init(param, _ev_loop);
    return sck;
  }
  if (auto* param = dynamic_cast<listen_stream_socket_parameters*>(stream_set);
      param) {
    auto sck = std::make_unique<tcp_listen_stream>();
    sck->init(param, _ev_loop);
    return sck;
  }
  return nullptr;
}

void ev_stream_factory::proceed() { ev::proceed(_ev_loop); }

}  // namespace jkl::sp::lnx
