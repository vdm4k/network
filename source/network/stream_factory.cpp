#ifdef WITH_SSL
#include <network/tcp/ssl/listen/stream.h>
#include <network/tcp/ssl/send/stream.h>
#endif
#ifdef WITH_SCTP
#include <network/sctp/listen/stream.h>
#include <network/sctp/send/stream.h>
#endif
#include <network/settings.h>
#include <network/stream_factory.h>
#include <network/tcp/listen/stream.h>

namespace bro::net {
ev_stream_factory::ev_stream_factory() noexcept : _ev_loop{ev::init()} {}

ev_stream_factory::~ev_stream_factory() { ev::clean_up(_ev_loop); }

strm::stream_ptr ev_stream_factory::create_stream(strm::settings *stream_set) {
#ifdef WITH_SCTP
  if (auto *param = dynamic_cast<sctp::listen::settings *>(stream_set); param) {
    auto sck = std::make_unique<sctp::listen::stream>();
    sck->init(param);
    return sck;
  }
  if (auto *param = dynamic_cast<sctp::send::settings *>(stream_set); param) {
    auto sck = std::make_unique<sctp::send::stream>();
    sck->init(param);
    return sck;
  }
#endif
#ifdef WITH_SSL
  if (auto *param = dynamic_cast<tcp::ssl::listen::settings *>(stream_set);
      param) {
    auto sck = std::make_unique<tcp::ssl::listen::stream>();
    sck->init(param);
    return sck;
  }
  if (auto *param = dynamic_cast<tcp::ssl::send::settings *>(stream_set);
      param) {
    auto sck = std::make_unique<tcp::ssl::send::stream>();
    sck->init(param);
    return sck;
  }
#endif
  if (auto *param = dynamic_cast<tcp::send::settings *>(stream_set); param) {
    auto sck = std::make_unique<tcp::send::stream>();
    sck->init(param);
    return sck;
  }
  if (auto *param = dynamic_cast<tcp::listen::settings *>(stream_set); param) {
    auto sck = std::make_unique<tcp::listen::stream>();
    sck->init(param);
    return sck;
  }
  return nullptr;
}

void ev_stream_factory::bind(strm::stream_ptr &stream) {
#ifdef WITH_SCTP
  if (auto *st = dynamic_cast<sctp::send::stream *>(stream.get()); st) {
    st->assign_loop(_ev_loop);
    return;
  }
  if (auto *st = dynamic_cast<sctp::listen::stream *>(stream.get()); st) {
    st->assign_loop(_ev_loop);
    return;
  }
#endif
  if (auto *st = dynamic_cast<tcp::send::stream *>(stream.get()); st) {
    st->assign_loop(_ev_loop);
    return;
  }
  if (auto *st = dynamic_cast<tcp::listen::stream *>(stream.get()); st) {
    st->assign_loop(_ev_loop);
    return;
  }
}

void ev_stream_factory::proceed() { ev::proceed(_ev_loop); }

} // namespace bro::net
