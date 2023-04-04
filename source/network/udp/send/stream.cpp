#include <network/platforms/system.h>
#include <network/udp/send/stream.h>

namespace bro::net::udp::send {

bool stream::init(settings *send_params) {
  _settings = *send_params;
  bool res = create_socket(_settings._peer_addr.get_address().get_version(), socket_type::e_udp);
  if (res && _settings._self_addr) {
    res = reuse_address(get_fd(), get_error_description())
          && bind_on_address(*_settings._self_addr, get_fd(), get_error_description());
  }
  // connect only afer bind
  if (res)
    res = connect();

  if (res) {
    set_connection_state(state::e_established);
  } else {
    cleanup();
  }
  return res;
}

ssize_t stream::receive(std::byte *buffer, size_t buffer_size) {
  ssize_t rec{0};
  while (true) {
    rec = ::recv(get_fd(), buffer, buffer_size, MSG_NOSIGNAL);
    if (rec > 0) {
      ++_statistic._success_recv_data;
      break;
    }

    if (EAGAIN == errno || EWOULDBLOCK == errno || EINTR == errno) {
      errno = 0;
      ++_statistic._retry_recv_data;
      continue;
    }

    // 0 may also be returned if the requested number of bytes to receive from a stream socket was 0
    if (buffer_size == 0 && rec == 0)
      break;

    set_detailed_error("recv return error");
    set_connection_state(state::e_failed);
    ++_statistic._failed_recv_data;
    rec = -1;
    break;
  }
  return rec;
}

bool stream::connect() {
  if (connect_stream(_settings._peer_addr, get_fd(), get_error_description()))
    return true;
  set_connection_state(state::e_failed);
  return false;
}

ssize_t stream::send_data(std::byte const *data, size_t data_size) {
  // start to send
  ssize_t sent{0};
  while (true) {
    sent = ::send(get_fd(), data, data_size, MSG_NOSIGNAL);
    if (sent > 0) {
      ++_statistic._success_send_data;
      break;
    }

    if (EAGAIN == errno || EWOULDBLOCK == errno || EINTR == errno) {
      errno = 0;
      ++_statistic._retry_send_data;
      continue;
    }

    // 0 may also be returned if the requested number of bytes to receive from a stream socket was 0
    if (data_size == 0 && sent == 0)
      break;

    set_detailed_error("send return error");
    set_connection_state(state::e_failed);
    ++_statistic._failed_send_data;
    sent = -1;
    break;
  }
  return sent;
}

void stream::reset_statistic() {
  _statistic.reset();
}

} // namespace bro::net::udp::send
