#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/tcp.h>
#include <network/libev/libev.h>
#include <network/stream.h>
#include <network/tcp/settings.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace bro::net {

stream::~stream() { cleanup(); }

std::string const &stream::get_detailed_error() const {
  return _detailed_error;
}

std::string &stream::get_detailed_error() { return _detailed_error; }

stream::state stream::get_state() const { return _state; }

void stream::set_state_changed_cb(strm::state_changed_cb cb,
                                  std::any user_data) {
  _state_changed_cb = cb;
  _param_state_changed_cb = user_data;
}

void stream::set_connection_state(state new_state) {
  _state = new_state;
  if (_state_changed_cb) _state_changed_cb(this, _param_state_changed_cb);
}

void stream::set_detailed_error(const std::string &str) {
  if (errno)
    _detailed_error = str + ", errno - " + strerror(errno);
  else
    _detailed_error = str;
}

void stream::cleanup() {
  if (-1 != _file_descr) {
    ::close(_file_descr);
    _file_descr = -1;
  }
}

}  // namespace bro::net
