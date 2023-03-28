#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/tcp.h>
#include <network/libev/libev.h>
#include <network/settings.h>
#include <network/stream.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace bro::net {

stream::~stream() {
  cleanup();
}

std::string const &stream::get_detailed_error() const {
  return _detailed_error;
}

std::string &stream::get_detailed_error() {
  return _detailed_error;
}

stream::state stream::get_state() const {
  return _state;
}

void stream::set_state_changed_cb(strm::state_changed_cb cb, std::any user_data) {
  _state_changed_cb = cb;
  _param_state_changed_cb = user_data;
}

void stream::set_connection_state(state new_state) {
  if (_state == new_state)
    return;
  _state = new_state;
  if (_state_changed_cb)
    _state_changed_cb(this, _param_state_changed_cb);
}

void stream::set_detailed_error(const std::string &str) {
  if (errno) {
    if (!_detailed_error.empty())
      _detailed_error += "; ";
    _detailed_error += str + ", errno - " + strerror(errno);
    errno = 0;
  } else
    _detailed_error = str;
}

bool stream::create_socket(proto::ip::address::version version, type tp) {
  int af_type = proto::ip::address::version::e_v6 == version ? AF_INET6 : AF_INET;
  int protocol = tp == type::e_sctp ? IPPROTO_SCTP : IPPROTO_TCP; // IPPROTO_TCP

  int rc = ::socket(af_type, SOCK_STREAM, protocol);
  if (rc == -1) {
    set_detailed_error("coulnd't create socket");
    set_connection_state(state::e_failed);
    return false;
  }

  _file_descr = rc;
  if (!set_socket_options() || !set_socket_specific_options(version)) {
    return false;
  }
  return true;
}

bool stream::set_socket_options() {
#ifdef FIONBIO
  int mode = 1;
  if (-1 == ioctl(_file_descr, FIONBIO, &mode)) {
    set_detailed_error("coulnd't set non blocking mode for socket");
    set_connection_state(state::e_failed);
    return false;
  }
#endif // FIONBIO
  settings *sparam = (settings *) get_settings();
  if (sparam->_buffer_size) {
    int optval = *sparam->_buffer_size;
#ifdef SO_SNDBUF
    if (-1 == setsockopt(_file_descr, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<char const *>(&optval), sizeof(optval))) {
      set_detailed_error("coulnd't set send buffer size");
      set_connection_state(state::e_failed);
      return false;
    }
#endif // SO_SNDBUF
#ifdef SO_RCVBUF
    if (-1 == setsockopt(_file_descr, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<char const *>(&optval), sizeof(optval))) {
      set_detailed_error("coulnd't set receive buffer size");
      set_connection_state(state::e_failed);
      return false;
    }
#endif // SO_RCVBUF
  }
  return true;
}

void stream::cleanup() {
  if (-1 != _file_descr) {
    if (-1 == ::close(_file_descr)) {
      set_detailed_error("close socket return an error");
      set_connection_state(state::e_failed);
    }
    _file_descr = -1;
  }
}

} // namespace bro::net
