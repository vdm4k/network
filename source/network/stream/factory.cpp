#ifdef WITH_TCP_SSL
#include <network/tcp/ssl/listen/stream.h>
#include <network/tcp/ssl/send/stream.h>
#endif // WITH_TCP_SSL
#ifdef WITH_SCTP
#include <network/sctp/listen/stream.h>
#include <network/sctp/send/stream.h>
#endif // WITH_SCTP
#ifdef WITH_SCTP_SSL
#include <network/sctp/ssl/listen/stream.h>
#include <network/sctp/ssl/send/stream.h>
#endif // WITH_SCTP_SSL
#ifdef WITH_UDP_SSL
#include <network/udp/ssl/listen/stream.h>
#include <network/udp/ssl/send/stream.h>
#endif // WITH_UDP_SSL
#include <network/stream/factory.h>
#include <network/tcp/listen/stream.h>
#include <network/tcp/send/stream.h>
#include <network/udp/send/stream.h>

namespace bro::net::ev {

strm::stream_ptr factory::create_stream(strm::settings *stream_set) {
#ifdef WITH_SCTP_SSL
  if (auto *param = dynamic_cast<sctp::ssl::listen::settings *>(stream_set); param) {
    auto sck = std::make_unique<sctp::ssl::listen::stream>();
    sck->init(param);
    return sck;
  }
  if (auto *param = dynamic_cast<sctp::ssl::send::settings *>(stream_set); param) {
    auto sck = std::make_unique<sctp::ssl::send::stream>();
    sck->init(param);
    return sck;
  }
#endif // WITH_SCTP_SSL
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
#endif // WITH_SCTP
#ifdef WITH_TCP_SSL
  if (auto *param = dynamic_cast<tcp::ssl::listen::settings *>(stream_set); param) {
    auto sck = std::make_unique<tcp::ssl::listen::stream>();
    sck->init(param);
    return sck;
  }
  if (auto *param = dynamic_cast<tcp::ssl::send::settings *>(stream_set); param) {
    auto sck = std::make_unique<tcp::ssl::send::stream>();
    sck->init(param);
    return sck;
  }
#endif // WITH_TCP_SSL
#ifdef WITH_UDP_SSL
  if (auto *param = dynamic_cast<udp::ssl::listen::settings *>(stream_set); param) {
    auto sck = std::make_unique<udp::ssl::listen::stream>();
    sck->init(param);
    return sck;
  }
  if (auto *param = dynamic_cast<udp::ssl::send::settings *>(stream_set); param) {
    auto sck = std::make_unique<udp::ssl::send::stream>();
    sck->init(param);
    return sck;
  }
#endif // WITH_UDP_SSL
  if (auto *param = dynamic_cast<udp::send::settings *>(stream_set); param) {
    auto sck = std::make_unique<udp::send::stream>();
    sck->init(param);
    return sck;
  }
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

void factory::bind(strm::stream_ptr &stream) {
  if (auto *st = dynamic_cast<bro::net::send::stream *>(stream.get()); st) {
    st->assign_events(_factory.generate_new_event(::bro::ev::event::type::e_read),
                      _factory.generate_new_event(::bro::ev::event::type::e_write));
  } else if (auto *st = dynamic_cast<bro::net::listen::stream *>(stream.get()); st) {
    st->assign_event(_factory.generate_new_event(::bro::ev::event::type::e_read));
  }
}

void factory::proceed() {
  _factory.proceed();
}

} // namespace bro::net::ev
