#ifdef WITH_SSL
#include <socket_proxy/linux/ssl/listen/stream.h>
#include <socket_proxy/linux/ssl/send/stream.h>
#endif
#include <socket_proxy/linux/stream_factory.h>
#include <socket_proxy/linux/tcp/listen/stream.h>
#include <socket_proxy/linux/tcp/send/stream.h>
#include <socket_proxy/linux/tcp/settings.h>

namespace bro::sp {
ev_stream_factory::ev_stream_factory() noexcept : _ev_loop{ev::init()} {}

ev_stream_factory::~ev_stream_factory() { ev::clean_up(_ev_loop); }

stream_ptr ev_stream_factory::create_stream(stream_settings* stream_set) {
#ifdef WITH_SSL
  if (auto* param = dynamic_cast<tcp::ssl::listen::settings*>(stream_set);
      param) {
    auto sck = std::make_unique<tcp::ssl::listen::stream>();
    sck->init(param);
    return sck;
  }
  if (auto* param = dynamic_cast<tcp::ssl::send::settings*>(stream_set);
      param) {
    auto sck = std::make_unique<tcp::ssl::send::stream>();
    sck->init(param);
    return sck;
  }
#endif
  if (auto* param = dynamic_cast<tcp::send::settings*>(stream_set); param) {
    auto sck = std::make_unique<tcp::send::stream>();
    sck->init(param);
    return sck;
  }
  if (auto* param = dynamic_cast<tcp::listen::settings*>(stream_set); param) {
    auto sck = std::make_unique<tcp::listen::stream>();
    sck->init(param);
    return sck;
  }
  return nullptr;
}

void ev_stream_factory::bind(stream_ptr& stream) {
  if (auto* st = dynamic_cast<tcp::send::stream*>(stream.get()); st) {
    st->assign_loop(_ev_loop);
    return;
  }
  if (auto* st = dynamic_cast<tcp::listen::stream*>(stream.get()); st) {
    st->assign_loop(_ev_loop);
    return;
  }
}

void ev_stream_factory::proceed() { ev::proceed(_ev_loop); }

}  // namespace bro::sp
