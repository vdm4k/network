#include <socket_proxy/libev/libev.h>
#include <socket_proxy/linux/tcp/listen/stream.h>
#include <socket_proxy/linux/tcp/send/stream.h>

namespace jkl::sp::lnx::tcp::listen {

void incoming_connection_cb(struct ev_loop * /*loop*/, ev_io *w,
                            int /*revents*/) {
  int new_fd = -1;
  auto *conn = reinterpret_cast<stream *>(w->data);

  jkl::proto::ip::full_address peer_addr;
  switch (conn->get_self_address().get_address().get_version()) {
    case jkl::proto::ip::address::version::e_v4: {
      struct sockaddr_in t_peer_addr = {0, 0, {0}, {0}};
      socklen_t addrlen = sizeof(t_peer_addr);
      while (true) {
        new_fd = accept(
            w->fd, reinterpret_cast<struct sockaddr *>(&t_peer_addr), &addrlen);
        if (-1 == new_fd) {
          if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) break;
        } else
          break;
      }

      if (-1 != new_fd) {
        peer_addr = jkl::proto::ip::full_address(
            jkl::proto::ip::v4::address(t_peer_addr.sin_addr.s_addr),
            htons(t_peer_addr.sin_port));
      }
      break;
    }
    case jkl::proto::ip::address::version::e_v6: {
      sockaddr_in6 t_peer_addr = {0, 0, 0, {{{0}}}, 0};
      socklen_t addrlen = sizeof(t_peer_addr);
      while (true) {
        new_fd = accept(
            w->fd, reinterpret_cast<struct sockaddr *>(&t_peer_addr), &addrlen);
        if (-1 == new_fd) {
          if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) break;
        } else
          break;
      }
      if (-1 != new_fd) {
        char addr_buf[50];
        inet_ntop(AF_INET6, &t_peer_addr.sin6_addr, addr_buf, sizeof(addr_buf));
        peer_addr =
            jkl::proto::ip::full_address(jkl::proto::ip::v6::address(addr_buf),
                                         htons(t_peer_addr.sin6_port));
      }
      break;
    }
    default:
      break;
  }

  jkl::proto::ip::full_address self_address;
  if (-1 != new_fd) {
    stream::get_local_address(peer_addr.get_address().get_version(), new_fd,
                              self_address);
  }
  conn->handle_incoming_connection(new_fd, peer_addr, self_address);
}

stream::~stream() { stop_events(); }

ssize_t stream::send(std::byte * /*data*/, size_t /*data_size*/) {
  set_detailed_error("couldn't send data by listen stream");
  return 0;
}

ssize_t stream::receive(std::byte * /*data*/, size_t /*data_size*/) {
  set_detailed_error("couldn't receive data in listen stream");
  return 0;
}

void stream::set_received_data_cb(received_data_cb /*cb*/, std::any /*param*/) {
}

void stream::set_send_data_cb(send_data_cb /*cb*/, std::any /*param*/) {}

bool stream::is_active() const { return get_state() == state::e_wait; }

void stream::reset_statistic() {
  _statistic._success_accept_connections = 0;
  _statistic._failed_to_accept_connections = 0;
}

bool stream::create_listen_socket() {
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

  return bind_on_address(_settings._listen_address);
}

void stream::handle_incoming_connection(
    int file_descr, jkl::proto::ip::full_address const &peer_addr,
    proto::ip::full_address const &self_addr) {
  auto sck = std::make_unique<send::stream>();

  if (-1 != file_descr) {
    _statistic._success_accept_connections++;
    sck->_settings._peer_addr = peer_addr;
    sck->_settings._self_addr = self_addr;
    sck->_file_descr = file_descr;
    sck->set_connection_state(state::e_established);
    sck->set_socket_specific_options();
  } else {
    _statistic._failed_to_accept_connections++;
    sck->set_connection_state(state::e_failed);
    sck->set_detailed_error("couldn't accept new incomming connection");
  }

  if (_settings._proc_in_conn)
    _settings._proc_in_conn(std::move(sck), _settings._in_conn_handler_data);
}

void stream::assign_loop(struct ev_loop *loop) {
  _loop = loop;
  ev::init(_connect_io, incoming_connection_cb, _file_descr, EV_READ, this);
  ev::start(_connect_io, _loop);
}

jkl::proto::ip::full_address const &stream::get_self_address() const {
  return _settings._listen_address;
}

bool stream::init(settings *listen_params) {
  bool res{false};
  _settings = *listen_params;
  if (create_listen_socket()) {
    set_connection_state(state::e_wait);
    if (0 == ::listen(_file_descr, _settings._listen_backlog)) {
      res = true;
    } else {
      set_detailed_error("server listen is failed");
      set_connection_state(state::e_failed);
      cleanup();
    }
  }
  return res;
}

void stream::stop_events() { ev::stop(_connect_io, _loop); }

}  // namespace jkl::sp::lnx::tcp::listen
