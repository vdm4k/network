#include <network/sctp/listen/stream.h>
#include <network/sctp/send/stream.h>
#include "network/platforms/system.h"

namespace bro::net::sctp::listen {

stream::~stream() {
  cleanup();
}

bool stream::create_listen_socket() {
  return create_socket(_settings._listen_address.get_address().get_version(), socket_type::e_sctp)
         && reuse_address(_file_descr, get_detailed_error())
         && bind_on_sctp_address(_settings._listen_address, _file_descr, get_detailed_error())
         && asconf_on(_file_descr, get_detailed_error())
         && start_listen(_file_descr, _settings._listen_backlog, get_detailed_error());
}

bool stream::fill_send_stream(accept_connection_res const &result, std::unique_ptr<strm::stream> &sck) {
  if (!net::listen::stream::fill_send_stream(result, sck))
    return false;

  auto *set = (sctp::settings *) sck->get_settings();
  set->_ppid = _settings._ppid;
  return true;
}

std::unique_ptr<strm::stream> stream::generate_send_stream() {
  return std::make_unique<bro::net::sctp::send::stream>();
}

proto::ip::full_address const &stream::get_self_address() const {
  return _settings._listen_address;
}

bool stream::init(settings *listen_params) {
  bool res{false};
  _settings = *listen_params;
  if (create_listen_socket()) {
    set_connection_state(state::e_wait);
    res = true;
  } else {
    set_connection_state(state::e_failed);
    cleanup();
  }
  return res;
}

void stream::cleanup() {
  net::listen::stream::cleanup();
}

bool stream::create_socket(proto::ip::address::version version, socket_type s_type) {
  if (!net::stream::create_socket(version, s_type)) {
    return false;
  }
  if (!set_sctp_options(version, (settings *) get_settings(), _file_descr, get_detailed_error())) {
    cleanup();
    return false;
  }
  return true;
}

} // namespace bro::net::sctp::listen
