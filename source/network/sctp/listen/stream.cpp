#include <network/sctp/listen/stream.h>
#include <network/sctp/send/stream.h>
#include "network/platforms/system.h"

namespace bro::net::sctp::listen {

bool stream::create_listen_socket() {
  if (create_socket(_settings._listen_address.get_address().get_version(), socket_type::e_sctp)
      && reuse_address(get_fd(), get_error_description())
      && bind_on_sctp_address(_settings._listen_address, get_fd(), get_error_description())
      && start_listen(get_fd(), _settings._listen_backlog, get_error_description()))
    return true;
  set_connection_state(state::e_failed);
  return false;
}

bool stream::fill_send_stream(accept_connection_res const &result, std::unique_ptr<net::stream> &sck) {
  if (!net::listen::stream::fill_send_stream(result, sck))
    return false;

  auto *set = (sctp::settings *) sck->get_settings();
  set->_ppid = _settings._ppid;
  return true;
}

std::unique_ptr<net::stream> stream::generate_send_stream() {
  return std::make_unique<bro::net::sctp::send::stream>();
}

bool stream::init(settings *listen_params) {
  _settings = *listen_params;
  if (create_listen_socket()) {
    set_connection_state(state::e_wait);
    return true;
  }
  return false;
}

bool stream::create_socket(proto::ip::address::version version, socket_type s_type) {
  if (!net::stream::create_socket(version, s_type)) {
    return false;
  }
  if (!set_sctp_options(version, (settings *) get_settings(), get_fd(), get_error_description())) {
    set_connection_state(state::e_failed);
    return false;
  }
  return true;
}

} // namespace bro::net::sctp::listen
