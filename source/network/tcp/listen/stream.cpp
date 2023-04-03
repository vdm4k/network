#include <network/platforms/system.h>
#include <network/tcp/listen/stream.h>
#include <network/tcp/send/stream.h>

namespace bro::net::tcp::listen {

stream::~stream() {
  cleanup();
}

bool stream::create_listen_socket() {
  return create_socket(_settings._listen_address.get_address().get_version(), socket_type::e_tcp)
         && reuse_address(get_fd(), get_detailed_error())
         && bind_on_address(_settings._listen_address, get_fd(), get_detailed_error())
         && start_listen(get_fd(), _settings._listen_backlog, get_detailed_error());
}

std::unique_ptr<strm::stream> stream::generate_send_stream() {
  return std::make_unique<tcp::send::stream>();
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

bool stream::create_socket(proto::ip::address::version version, socket_type s_type) {
  if (!net::stream::create_socket(version, s_type)) {
    return false;
  }
  if (!set_tcp_options(get_fd(), get_detailed_error())) {
    cleanup();
    return false;
  }
  return true;
}

void stream::cleanup() {
  bro::net::stream::cleanup();
}

} // namespace bro::net::tcp::listen
