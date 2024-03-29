#include <network/stream/send/settings.h>
#include <network/platforms/system.h>
#include <network/stream/send/stream.h>

namespace bro::net::send {

stream::~stream() {
  stream::cleanup();
}

void stream::stop_events() {
  if (_read)
    _read->stop();
  if (_write)
    _write->stop();
}

void stream::assign_events(bro::ev::io_t &&read, bro::ev::io_t &&write) {
  _buffer_send = ((net::send::settings *) (get_settings()))->_buffer_send;
  _read = std::move(read);
  _write = std::move(write);
  if (state::e_established == get_state()) {
    _read->start(get_fd(), std::function<void()>(std::bind(&stream::receive_data, this)));
    _write->set_callback(std::function<void()>(std::bind(&stream::send_buffered_data, this)));
    enable_send_cb();
  } else {
    _write->start(get_fd(), std::function<void()>(std::bind(&stream::connection_established, this)));
  }
}

bool stream::connection_established() {
  if (!is_connection_established(get_fd(), get_error_description())) {
    set_connection_state(state::e_failed);
    return false;
  }

  if (get_state() != state::e_wait) {
    set_detailed_error(std::string("connection established, but stream not in "
                                   "listen state. state is - ")
                       + state_to_string(get_state()));
    return false;
  }

  disable_send_cb();
  _write->set_callback(std::function<void()>(std::bind(&stream::send_buffered_data, this)));
  enable_send_cb();
  _read->start(get_fd(), std::function<void()>(std::bind(&stream::receive_data, this)));
  return true;
}

ssize_t stream::send(std::byte const *data, size_t data_size) {
  // check stream state
  switch (get_state()) {
  case state::e_established:
    break;
  case state::e_wait: {
    if (!_buffer_send)
      return 0;
    _send_buffer.append(data, data_size);
    return data_size;
  }
  case state::e_failed:
    [[fallthrough]];
  case state::e_closed: {
    return -1;
  }
  default:
    break;
  }

  // check buffer is not empty
  if (!_send_buffer.is_empty()) {
    _send_buffer.append(data, data_size);
    return data_size;
  }

  ssize_t sent = send_data(data, data_size);
  if (!_buffer_send)
    return sent;
  if (sent >= 0 && (size_t) sent != data_size) {
    _send_buffer.append(data + sent, data_size - sent);
    enable_send_cb();
    return data_size;
  }
  return sent;
}

void stream::set_received_data_cb(strm::received_data_cb cb, std::any user_data) {
  _received_data_cb = cb;
  _param_received_data_cb = user_data;
}

void stream::set_send_data_cb(strm::received_data_cb cb, std::any param) {
  _send_data_cb = cb;
  _param_send_data_cb = param;
  if (_send_data_cb)
    _write->start(get_fd(), [&]() { _send_data_cb(this, _param_send_data_cb); });
  else
    _write->stop();
}

bool stream::is_active() const {
  auto st = get_state();
  return st == state::e_wait || st == state::e_established;
}

void stream::receive_data() {
  if (_received_data_cb)
    _received_data_cb(this, _param_received_data_cb);
}

void stream::send_buffered_data() {
  if (_send_buffer.is_empty()) {
    disable_send_cb();
    return;
  }

  // check stream state
  switch (get_state()) {
  case state::e_established: {
    auto data = _send_buffer.get_data();
    auto sent = send_data(data.first, data.second);
    if (sent > 0)
      _send_buffer.erase(sent);
    else if (sent < 0)
      _send_buffer.clear();
    break;
  }
  case state::e_wait: {
    break;
  }
  case state::e_failed:
    [[fallthrough]];
  case state::e_closed: {
    _send_buffer.clear();
    return;
  }
  default:
    break;
  }

  if (_send_buffer.is_empty())
    disable_send_cb();
}

void stream::disable_send_cb() {
  _write->stop();
}

void stream::enable_send_cb() {
  if (!_send_buffer.is_empty())
    _write->start(get_fd());
}

void stream::cleanup() {
  stop_events();
  net::stream::cleanup();
}

} // namespace bro::net::send
