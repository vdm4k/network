#include <network/stream/settings.h>
#include <network/stream/stream.h>

namespace bro::net {

stream::~stream() {
  stream::cleanup();
}

std::string const &stream::get_error_description() const {
  return _err;
}

std::string &stream::get_error_description() {
  return _err;
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
  if (state::e_failed == _state)
    cleanup();
  if (_state_changed_cb)
    _state_changed_cb(this, _param_state_changed_cb);
}

void stream::set_detailed_error(std::string const &err) {
  append_error(_err, err);
  set_connection_state(state::e_failed);
}

void stream::set_detailed_error(char const *const err) {
  append_error(_err, err);
  set_connection_state(state::e_failed);
}

bool stream::create_socket(proto::ip::address::version version, socket_type s_type) {
  auto file_descr = bro::net::create_socket(version, s_type, get_error_description());
  if (!file_descr) {
    set_connection_state(state::e_failed);
    return false;
  }

  _file_descr = *file_descr;
  if (!set_socket_options()) {
    set_connection_state(state::e_failed);
    return false;
  }
  return true;
}

bool stream::set_socket_options() {
  settings *set = (settings *) get_settings();
  if (set->_non_blocking_socket && !set_non_blocking_mode(_file_descr, get_error_description()))
    return false;

  if (set->_buffer_size && !set_socket_buffer_size(_file_descr, *set->_buffer_size, get_error_description()))
    return false;

  return true;
}

void stream::cleanup() {
  bro::net::close_socket(_file_descr, get_error_description());
}

} // namespace bro::net
