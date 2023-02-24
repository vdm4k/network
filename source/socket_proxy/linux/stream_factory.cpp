#include <socket_proxy/linux/stream_factory.h>
#include <socket_proxy/linux/tcp/listen_stream.h>
#include <socket_proxy/linux/tcp/send_stream.h>
#include <socket_proxy/linux/tcp/settings.h>

namespace jkl::sp::lnx {
ev_stream_factory::ev_stream_factory() noexcept : _ev_loop{ev::init()} {}

ev_stream_factory::~ev_stream_factory() { ev::clean_up(_ev_loop); }

stream_ptr ev_stream_factory::create_stream(stream_settings* stream_set) {
  if (auto* param =
          dynamic_cast<tcp::send_stream_parameters*>(stream_set);
      param) {
    auto sck = std::make_unique<tcp::send_stream>();
    sck->init(param);
    return sck;
  }
  if (auto* param =
          dynamic_cast<tcp::listen_stream_parameters*>(stream_set);
      param) {
    auto sck = std::make_unique<tcp::listen_stream>();
    sck->init(param);
    return sck;
  }
  return nullptr;
}

void ev_stream_factory::bind(stream_ptr& stream) {
  if (auto* st = dynamic_cast<tcp::listen_stream*>(stream.get()); st) {
    st->assign_loop(_ev_loop);
    return;
  }
  if (auto* st = dynamic_cast<tcp::send_stream*>(stream.get()); st) {
    st->assign_loop(_ev_loop);
  }
}

void ev_stream_factory::proceed() { ev::proceed(_ev_loop); }

}  // namespace jkl::sp::lnx
