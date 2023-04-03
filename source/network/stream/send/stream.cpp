#include <network/platforms/system.h>
#include <network/stream/send/stream.h>

namespace bro::net::send {

stream::~stream() {
  stop_events();
}

void receive_data_cb(struct ev_loop *, ev_io *w, int) {
  auto *conn = reinterpret_cast<stream *>(w->data);
  conn->receive_data();
}

void send_data_cb(struct ev_loop *, ev_io *w, int) {
  auto *conn = reinterpret_cast<stream *>(w->data);
  conn->send_buffered_data();
}

void connection_established_cb(struct ev_loop *, ev_io *w, int) {
  auto *tr = reinterpret_cast<stream *>(w->data);
  tr->connection_established();
}

void stream::stop_events() {
  ev::stop(_read_io, _loop);
  ev::stop(_write_io, _loop);
}

void stream::assign_loop(struct ev_loop *loop) {
  stop_events();
  _loop = loop;
  ev::init_io(_read_io, receive_data_cb, get_fd(), EV_READ, this);
  if (state::e_established == get_state()) {
    ev::init_io(_write_io, send_data_cb, get_fd(), EV_WRITE, this);
    ev::start(_read_io, _loop);
    enable_send_cb();
  } else {
    ev::init_io(_write_io, connection_established_cb, get_fd(), EV_WRITE, this);
    ev::start(_write_io, _loop);
  }
}

bool stream::connection_established() {
  if (!is_connection_established(get_fd(), get_error_description())) {
    set_connection_state(state::e_failed);
    return false;
  }

  if (get_state() != state::e_wait) {
    set_detailed_error(std::string("connection established, but tcp state not in "
                                   "listen state. state is - ")
                       + state_to_string(get_state()));
    set_connection_state(state::e_failed);
    return false;
  }

  ev::stop(_write_io, _loop);
  ev::init_io(_write_io, send_data_cb, get_fd(), EV_WRITE, this);
  ev::start(_read_io, _loop);
  enable_send_cb();
  set_connection_state(state::e_established);
  return true;
}

ssize_t stream::send(std::byte const *data, size_t data_size) {
  // check stream state
  switch (get_state()) {
  case state::e_established:
    break;
  case state::e_wait: {
    _send_buffer.append(data, data_size);
    enable_send_cb();
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
  ev::stop(_write_io, _loop);
}

void stream::enable_send_cb() {
  if (!_send_buffer.is_empty())
    ev::start(_write_io, _loop);
}

void stream::cleanup() {
  stop_events();
  net::stream::cleanup();
}

} // namespace bro::net::send
