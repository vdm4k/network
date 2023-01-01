#pragma once
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <socket_proxy/linux/libev.h>
#include <socket_proxy/linux/tcp_stream.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace jkl::sp::lnx {

void receive_data_cb(struct ev_loop *, ev_io *w, int) {
  auto *conn = reinterpret_cast<tcp_stream *>(w->data);
  conn->receive_data();
}

void send_data_cb(struct ev_loop *, ev_io *w, int) {
  auto *conn = reinterpret_cast<tcp_stream *>(w->data);
  conn->send_data();
}

void connection_established_cb(struct ev_loop *, ev_io *w, int) {
  auto *tr = reinterpret_cast<tcp_stream *>(w->data);
  tr->connection_established();
}

void incoming_connection_cb(struct ev_loop * /*loop*/, ev_io *w,
                            int /*revents*/) {
  int new_fd = -1;
  auto *conn = reinterpret_cast<tcp_stream *>(w->data);
  struct sockaddr_in peer_addr = {0, 0, {0}, {0}};
  socklen_t addrlen = sizeof(peer_addr);
  while (true) {
    new_fd = accept(w->fd, reinterpret_cast<struct sockaddr *>(&peer_addr),
                    &addrlen);
    if (-1 == new_fd) {
      if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) break;
    } else
      break;
  }
  conn->handle_incoming_connection(new_fd, peer_addr);
}

tcp_stream::~tcp_stream() { cleanup(); }

void tcp_stream::set_socket_specific_options() {
  {
    int mode = 1;
    ioctl(_file_descr, FIONBIO, &mode);

    int optval = 32000;
#ifdef SO_SNDBUF
    if (-1 == setsockopt(_file_descr, SOL_SOCKET, SO_SNDBUF,
                         reinterpret_cast<char const *>(&optval),
                         sizeof(optval))) {
    }
#endif
#ifdef SO_RCVBUF
    if (-1 == setsockopt(_file_descr, SOL_SOCKET, SO_RCVBUF,
                         reinterpret_cast<char const *>(&optval),
                         sizeof(optval))) {
    }
#endif  // SO_SNDBUF
  }
  /* Set the NODELAY option (Nagle-like algorithm) */
  int optval = 1;
#ifdef TCP_NODELAY
  if (-1 == ::setsockopt(_file_descr, IPPROTO_TCP, TCP_NODELAY,
                         reinterpret_cast<char const *>(&optval),
                         sizeof(optval))) {
  }
#endif  // TCP_NODELAY
}

bool tcp_stream::create_socket() {
  int rc = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (-1 != rc) {
    _file_descr = rc;
    set_socket_specific_options();

  } else {
    set_detailed_error("couldn't create socket\n");
  }
  return rc != -1;
}

bool tcp_stream::fill_addr(proto::ip_addr const &ipaddr, uint16_t port,
                           sockaddr_in &addr) {
  addr = {0, 0, {0}, {0}};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = ipaddr.to_v4().get_data();
  addr.sin_port = __builtin_bswap16(port);
  return addr.sin_addr.s_addr != (in_addr_t)-1;
}

bool tcp_stream::connect_to_server(proto::ip_addr const &peer_addr,
                                   uint16_t peer_port, struct ev_loop *loop) {
  bool res = false;
  if (!fill_addr(peer_addr, peer_port, _peer_addr)) return res;
  if (create_socket()) {
    init_events(loop);
    if (connect()) {
      res = true;
    } else {
      set_connection_state(state::e_failed);
      cleanup();
    }
  } else {
    set_connection_state(state::e_failed);
  }
  return res;
}

bool tcp_stream::create_listen_tcp_socket() {
  if (!create_socket()) return false;
  int reuseaddr = 1;
  if (-1 == setsockopt(_file_descr, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const void *>(&reuseaddr),
                       sizeof(int))) {
    set_detailed_error("couldn't set option SO_REUSEADDR");
    ::close(_file_descr);
    _file_descr = -1;
    return false;
  }

  if (0 != ::bind(_file_descr, reinterpret_cast<sockaddr *>(&_self_addr),
                  sizeof(_self_addr))) {
    set_detailed_error("couldn't bind on address");
    ::close(_file_descr);
    _file_descr = -1;
    return false;
  }

  return true;
}

bool tcp_stream::bind_as_server(const proto::ip_addr &peer_addr,
                                uint16_t peer_port, struct ev_loop *loop,
                                proccess_incoming_conn_cb incom_con,
                                std::any asoc_data) {
  bool res{false};
  if (!fill_addr(peer_addr, peer_port, _self_addr)) return res;
  _incom_con_cb = incom_con;
  _param_incom_con_cb = asoc_data;
  if (create_listen_tcp_socket()) {
    _loop = loop;
    set_connection_state(state::e_listen);
    ev::init(&_connect_io, incoming_connection_cb, _file_descr, EV_READ, this);
    if (0 == listen(_file_descr, 14)) {
      ev::start(_connect_io, _loop);
      res = true;
    } else {
      set_detailed_error("server listen is failed");
      set_connection_state(state::e_failed);
      cleanup();
    }
  }
  return res;
}

void tcp_stream::init_events(struct ev_loop *loop) {
  _loop = loop;
  ev::init(&_read_io, receive_data_cb, _file_descr, EV_READ, this);
  ev::init(&_write_io, send_data_cb, _file_descr, EV_WRITE, this);
  ev::init(&_connect_io, connection_established_cb, _file_descr, EV_WRITE,
           this);
}

void tcp_stream::stop_events() {
  ev::stop(_read_io, _loop);
  ev::stop(_write_io, _loop);
  ev::stop(_connect_io, _loop);
}

void tcp_stream::cleanup() {
  if (-1 != _file_descr) {
    stop_events();
    ::close(_file_descr);
    _file_descr = -1;
  }
}

ssize_t tcp_stream::send(std::byte *data, size_t data_size) {
  ssize_t sent{0};
  while (true) {
    sent = ::send(_file_descr, data, data_size, MSG_NOSIGNAL);
    if (sent > 0) break;
    if (ssize_t(-1) == sent) {
      if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) {
        set_detailed_error("error occured while send data");
        set_connection_state(state::e_failed);
        break;
      }
    } else {
      set_connection_state(state::e_failed);
      set_detailed_error("socket error occured while send data");
      break;
    }
  }
  return sent;
}

ssize_t tcp_stream::receive(std::byte *buffer, size_t buffer_size) {
  ssize_t rec{0};
  while (true) {
    rec = ::recv(_file_descr, buffer, buffer_size, MSG_NOSIGNAL);
    if (rec > 0) break;

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
        set_connection_state(state::e_failed);
        set_detailed_error("recv return error");
        break;
      }
    }
  }
  return rec;
}

tcp_stream::state tcp_stream::get_state() const { return _state; }

void tcp_stream::set_received_data_cb(received_data_cb cb, std::any user_data) {
  _received_data_cb = cb;
  _param_received_data_cb = user_data;
}

void tcp_stream::set_send_data_cb(::jkl::send_data_cb cb, std::any user_data) {
  _send_data_cb = cb;
  _param_send_data_cb = user_data;
}

void tcp_stream::set_state_changed_cb(state_changed_cb cb, std::any user_data) {
  _state_changed_cb = cb;
  _param_state_changed_cb = user_data;
}

void tcp_stream::receive_data() {
  if (_received_data_cb) _received_data_cb(this, _param_received_data_cb);
}

void tcp_stream::send_data() {
  if (_send_data_cb) _send_data_cb(this, _param_send_data_cb);
}

bool tcp_stream::connect() {
  bool res{false};
  int rc =
      ::connect(_file_descr, reinterpret_cast<struct sockaddr *>(&_peer_addr),
                sizeof(_peer_addr));
  if (0 == rc || EINPROGRESS == errno) {
    ev::start(_connect_io, _loop);
    set_connection_state(state::e_listen);
    res = true;
  } else {
    if (0 != rc) {
      set_detailed_error("coulnd't connect to server");
    }
  }
  return res;
}

void tcp_stream::connection_established() {
  int err = -1;
  socklen_t len = sizeof(err);
  int rc = getsockopt(_file_descr, SOL_SOCKET, SO_ERROR, &err, &len);

  if (0 == rc) {
    if (0 == err) {
      if (_state == state::e_listen) {
        ev::stop(_connect_io, _loop);
        ev::start(_read_io, _loop);
        set_connection_state(state::e_established);
      } else {
        set_detailed_error(
            std::string("client connection established, but tcp state not in "
                        "listen state. state is - ") +
            connection_state_to_str(_state));
        set_connection_state(state::e_failed);
      }
    } else {
      set_detailed_error("client connection not established");
      set_connection_state(state::e_failed);
    }
  } else {
    set_detailed_error("getsockopt error");
    set_connection_state(state::e_failed);
  }
}

void tcp_stream::handle_incoming_connection(int file_descr,
                                            sockaddr_in peer_addr) {
  auto sck = std::make_unique<tcp_stream>();
  sck->_peer_addr = peer_addr;

  if (-1 != file_descr) {
    sck->_file_descr = file_descr;
    sck->_loop = _loop;
    sck->_state = state::e_established;

    set_socket_specific_options();
    sck->init_events(_loop);
    ev::start(sck->_read_io, _loop);
  } else {
    sck->_state = state::e_failed;
    sck->set_detailed_error("couldn't accept new incomming connection");
  }

  if (_incom_con_cb) _incom_con_cb(std::move(sck), _param_incom_con_cb);
}

void tcp_stream::set_connection_state(state new_state) {
  _state = new_state;
  if (_state_changed_cb) _state_changed_cb(this, _param_state_changed_cb);
}

void tcp_stream::set_detailed_error(const std::string &str) {
  if (errno)
    _detailed_error = str + ", errno - " + strerror(errno);
  else
    _detailed_error = str;
}

}  // namespace jkl::sp::lnx
