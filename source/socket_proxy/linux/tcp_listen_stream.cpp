#include <socket_proxy/libev/libev.h>
#include <socket_proxy/linux/tcp_listen_stream.h>
#include <socket_proxy/linux/tcp_send_stream.h>

namespace jkl::sp::lnx {

void incoming_connection_cb(struct ev_loop * /*loop*/, ev_io *w,
                            int /*revents*/) {
  int new_fd = -1;
  auto *conn = reinterpret_cast<tcp_listen_stream *>(w->data);
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

tcp_listen_stream::~tcp_listen_stream() { stop_events(); }

ssize_t tcp_listen_stream::send(std::byte * /*data*/, size_t /*data_size*/) {
  set_detailed_error("couldn't send data in listen stream");
  return 0;
}

ssize_t tcp_listen_stream::receive(std::byte * /*data*/, size_t /*data_size*/) {
  set_detailed_error("couldn't receive data in listen stream");
  return 0;
}

void tcp_listen_stream::set_received_data_cb(received_data_cb /*cb*/,
                                             std::any /*param*/) {}

void tcp_listen_stream::set_send_data_cb(send_data_cb /*cb*/,
                                         std::any /*param*/) {}

bool tcp_listen_stream::create_listen_socket() {
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

  return bind_on_address();
}

void tcp_listen_stream::handle_incoming_connection(int file_descr,
                                                   sockaddr_in peer_addr) {
  auto sck = std::make_unique<tcp_send_stream>();
  sck->_peer_addr = peer_addr;

  if (-1 != file_descr) {
    sck->_file_descr = file_descr;
    sck->_loop = _loop;
    sck->set_connection_state(state::e_established);

    set_socket_specific_options();
    sck->init_events(_loop);
    ev::start(sck->_read_io, _loop);
    get_local_address(_self_addr_full.get_address().get_version(),
                      sck->_file_descr, sck->_self_addr_full);
  } else {
    sck->set_connection_state(state::e_failed);
    sck->set_detailed_error("couldn't accept new incomming connection");
  }

  if (_listen_stream_socket_parameters._proc_in_conn)
    _listen_stream_socket_parameters._proc_in_conn(
        std::move(sck), _listen_stream_socket_parameters._in_conn_handler_data);
}

bool tcp_listen_stream::init(listen_stream_socket_parameters *listen_params,
                             struct ev_loop *loop) {
  bool res{false};
  _listen_stream_socket_parameters = *listen_params;
  if (!fill_sockaddr(_listen_stream_socket_parameters._listen_address,
                     _self_addr))
    return res;
  if (create_listen_socket()) {
    _loop = loop;
    set_connection_state(state::e_wait);
    ev::init(&_connect_io, incoming_connection_cb, _file_descr, EV_READ, this);
    if (0 ==
        listen(_file_descr, _listen_stream_socket_parameters._listen_backlog)) {
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

void tcp_listen_stream::stop_events() { ev::stop(_connect_io, _loop); }

}  // namespace jkl::sp::lnx
