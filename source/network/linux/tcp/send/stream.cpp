#include <network/libev/libev.h>
#include <network/linux/tcp/send/stream.h>

namespace bro::net::tcp::send {

stream::~stream() { stop_events(); }

void receive_data_cb(struct ev_loop *, ev_io *w, int) {
  auto *conn = reinterpret_cast<stream *>(w->data);
  conn->receive_data();
}

void send_data_cb(struct ev_loop *, ev_io *w, int) {
  auto *conn = reinterpret_cast<stream *>(w->data);
  conn->send_data();
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
  ev::init(_read_io, receive_data_cb, _file_descr, EV_READ, this);
  if (state::e_established == get_state()) {
    ev::init(_write_io, send_data_cb, _file_descr, EV_WRITE, this);
    if (_send_data_cb) {
      ev::start(_write_io, _loop);
    }
    ev::start(_read_io, _loop);
  } else {
    ev::init(_write_io, connection_established_cb, _file_descr, EV_WRITE, this);
    ev::start(_write_io, _loop);
  }
}

bool stream::init(settings *send_params) {
  bool res = false;
  _settings = *send_params;

  if (!create_socket()) {
    set_detailed_error("coulnd't create socket");
    set_connection_state(state::e_failed);
    return res;
  }
  if (!connect()) {
    set_detailed_error("coulnd't connect to server");
    set_connection_state(state::e_failed);
    cleanup();
    return res;
  }
  set_connection_state(state::e_wait);
  res = true;
  return res;
}

void stream::connection_established() {
  int err = -1;
  socklen_t len = sizeof(err);
  int rc = getsockopt(_file_descr, SOL_SOCKET, SO_ERROR, &err, &len);

  if (0 != rc) {
    set_detailed_error("getsockopt error");
    set_connection_state(state::e_failed);
    return;
  }
  if (0 != err) {
    set_detailed_error("connection not established");
    set_connection_state(state::e_failed);
    return;
  }

  if (get_state() != state::e_wait) {
    set_detailed_error(
        std::string("connection established, but tcp state not in "
                    "listen state. state is - ") +
        connection_state_to_str(get_state()));
    set_connection_state(state::e_failed);
    return;
  }

  ev::stop(_write_io, _loop);
  ev::init(_write_io, send_data_cb, _file_descr, EV_WRITE, this);
  if (_send_data_cb) ev::start(_write_io, _loop);
  ev::start(_read_io, _loop);
  set_connection_state(state::e_established);
}

ssize_t stream::send(std::byte *data, size_t data_size) {
  ssize_t sent{0};
  while (true) {
    sent = ::send(_file_descr, data, data_size, MSG_NOSIGNAL);
    if (sent > 0) {
      ++_statistic._success_send_data;
      return sent;
    }
    if (ssize_t(-1) == sent) {
      if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) {
        set_detailed_error("error occured while send data");
        set_connection_state(state::e_failed);
        break;
      }
    } else {
      set_detailed_error("socket error occured while send data");
      set_connection_state(state::e_failed);
      break;
    }
    ++_statistic._retry_send_data;
  }
  ++_statistic._failed_send_data;
  return sent;
}

ssize_t stream::receive(std::byte *buffer, size_t buffer_size) {
  ssize_t rec{0};
  while (true) {
    rec = ::recv(_file_descr, buffer, buffer_size, MSG_NOSIGNAL);
    if (rec > 0) {
      ++_statistic._success_recv_data;
      return rec;
    }

    if (0 == rec) {
      set_detailed_error("recv return 0 bytes");
      set_connection_state(state::e_failed);
      break;
    } else {
      if (ssize_t(-1) == rec) {
        if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) {
          set_detailed_error("recv return -1");
          set_connection_state(state::e_failed);
          break;
        }
      } else {
        set_detailed_error("recv return error");
        set_connection_state(state::e_failed);
        break;
      }
    }
    ++_statistic._retry_recv_data;
  }
  ++_statistic._failed_recv_data;
  return rec;
}

settings *stream::current_settings() { return &_settings; }

bool stream::connect() {
  sockaddr_in peer_addr;
  if (!fill_sockaddr(_settings._peer_addr, peer_addr)) return false;
  int rc =
      ::connect(_file_descr, reinterpret_cast<struct sockaddr *>(&peer_addr),
                sizeof(peer_addr));
  return (0 == rc || EINPROGRESS == errno);
}

void stream::set_received_data_cb(received_data_cb cb, std::any user_data) {
  _received_data_cb = cb;
  _param_received_data_cb = user_data;
}

void stream::set_send_data_cb(bro::send_data_cb cb, std::any user_data) {
  _send_data_cb = cb;
  _param_send_data_cb = user_data;
  if (_send_data_cb)
    ev::start(_write_io, _loop);
  else
    ev::stop(_write_io, _loop);
}

bool stream::is_active() const {
  auto st = get_state();
  return st == state::e_wait || st == state::e_established;
}

void stream::reset_statistic() {
  _statistic._success_send_data = 0;
  _statistic._retry_send_data = 0;
  _statistic._failed_send_data = 0;
  _statistic._success_recv_data = 0;
  _statistic._retry_recv_data = 0;
  _statistic._failed_recv_data = 0;
}

void stream::receive_data() {
  if (_received_data_cb) _received_data_cb(this, _param_received_data_cb);
}

void stream::send_data() {
  if (_send_data_cb) _send_data_cb(this, _param_send_data_cb);
}

void stream::cleanup() {
  tcp::stream::cleanup();
  stop_events();
}

}  // namespace bro::net::tcp::send
