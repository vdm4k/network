//#include <network/platforms/system.h>
//#include <network/platforms/libev/libev.h>
//#include <network/udp/send/stream.h>

//namespace bro::net::udp::send {

//stream::~stream() {
//  stop_events();
//}

//void receive_data_cb(struct ev_loop *, ev_io *w, int) {
//  auto *conn = reinterpret_cast<stream *>(w->data);
//  conn->receive_data();
//}

//void send_data_cb(struct ev_loop *, ev_io *w, int) {
//  auto *conn = reinterpret_cast<stream *>(w->data);
//  conn->send_data();
//}

//void connection_established_cb(struct ev_loop *, ev_io *w, int) {
//  auto *tr = reinterpret_cast<stream *>(w->data);
//  tr->connection_established();
//}

//void stream::stop_events() {
//  ev::stop(_read_io, _loop);
//  ev::stop(_write_io, _loop);
//}

//void stream::assign_loop(struct ev_loop *loop) {
//  stop_events();
//  _loop = loop;
//  ev::init(_read_io, receive_data_cb, _file_descr, EV_READ, this);
//  if (state::e_established == get_state()) {
//    ev::init(_write_io, send_data_cb, _file_descr, EV_WRITE, this);
//    //    if (_send_data_cb) {
//    //      ev::start(_write_io, _loop);
//    //    }
//    ev::start(_read_io, _loop);
//  } else {
//    ev::init(_write_io, connection_established_cb, _file_descr, EV_WRITE, this);
//    ev::start(_write_io, _loop);
//  }
//}

//bool stream::init(settings *send_params) {
//  _settings = *send_params;
//  bool res = create_socket(_settings._peer_addr.get_address().get_version(), type::e_tcp) && connect();
//  if (res && _settings._self_addr) {
//    res = reuse_address(_file_descr, get_detailed_error())
//          && bind_on_address(*_settings._self_addr, _file_descr, get_detailed_error());
//  }

//  if (res) {
//    set_connection_state(state::e_wait);
//  } else {
//    cleanup();
//  }
//  return res;
//}

//bool stream::connection_established() {
//  int err = -1;
//  socklen_t len = sizeof(err);
//  int rc = getsockopt(_file_descr, SOL_SOCKET, SO_ERROR, &err, &len);

//  if (0 != rc) {
//    set_detailed_error("getsockopt error");
//    set_connection_state(state::e_failed);
//    return false;
//  }
//  if (0 != err) {
//    set_detailed_error("connection not established");
//    set_connection_state(state::e_failed);
//    return false;
//  }

//  if (get_state() != state::e_wait) {
//    set_detailed_error(std::string("connection established, but tcp state not in "
//                                   "listen state. state is - ")
//                       + connection_state_to_str(get_state()));
//    set_connection_state(state::e_failed);
//    return false;
//  }

//  ev::stop(_write_io, _loop);
//  ev::init(_write_io, send_data_cb, _file_descr, EV_WRITE, this);
//  //  if (_send_data_cb)
//  //    ev::start(_write_io, _loop);
//  ev::start(_read_io, _loop);
//  set_connection_state(state::e_established);
//  return true;
//}

//ssize_t stream::send(std::byte const *data, size_t data_size) {
//  ssize_t sent{0};
//  while (true) {
//    sent = ::send(_file_descr, data, data_size, MSG_NOSIGNAL);
//    if (sent > 0) {
//      ++_statistic._success_send_data;
//      break;
//    }

//    if (EAGAIN == errno || EWOULDBLOCK == errno || EINTR == errno) {
//      errno = 0;
//      ++_statistic._retry_send_data;
//      continue;
//    }

//    // 0 may also be returned if the requested number of bytes to receive from a stream socket was 0
//    if (data_size == 0 && sent == 0)
//      break;

//    set_detailed_error("send return error");
//    set_connection_state(state::e_failed);
//    ++_statistic._failed_send_data;
//    sent = -1;
//    break;
//  }
//  return sent;
//}

//ssize_t stream::receive(std::byte *buffer, size_t buffer_size) {
//  ssize_t rec{0};
//  while (true) {
//    rec = ::recv(_file_descr, buffer, buffer_size, MSG_NOSIGNAL);
//    if (rec > 0) {
//      ++_statistic._success_recv_data;
//      break;
//    }

//    if (EAGAIN == errno || EWOULDBLOCK == errno || EINTR == errno) {
//      errno = 0;
//      ++_statistic._retry_recv_data;
//      continue;
//    }

//    // 0 may also be returned if the requested number of bytes to receive from a stream socket was 0
//    if (buffer_size == 0 && rec == 0)
//      break;

//    set_detailed_error("recv return error");
//    set_connection_state(state::e_failed);
//    ++_statistic._failed_recv_data;
//    rec = -1;
//    break;
//  }
//  return rec;
//}

//settings *stream::current_settings() {
//  return &_settings;
//}

//bool stream::connect() {
//  if (connect_stream(_settings._peer_addr, _file_descr, get_detailed_error()))
//    return true;
//  set_connection_state(state::e_failed);
//  return false;
//}

//void stream::set_received_data_cb(strm::received_data_cb cb, std::any user_data) {
//  _received_data_cb = cb;
//  _param_received_data_cb = user_data;
//}

//bool stream::is_active() const {
//  auto st = get_state();
//  return st == state::e_wait || st == state::e_established;
//}

//void stream::reset_statistic() {
//  _statistic._success_send_data = 0;
//  _statistic._retry_send_data = 0;
//  _statistic._failed_send_data = 0;
//  _statistic._success_recv_data = 0;
//  _statistic._retry_recv_data = 0;
//  _statistic._failed_recv_data = 0;
//}

//void stream::receive_data() {
//  if (_received_data_cb)
//    _received_data_cb(this, _param_received_data_cb);
//}

//void stream::send_data() {
//  //  if (_send_data_cb)
//  //    _send_data_cb(this, _param_send_data_cb);
//}

//void stream::disable_send_cb() {
//  //  if (_send_data_cb) {
//  //    swap(_send_data_dup_cb, _send_data_cb);
//  //    swap(_param_send_data_dup_cb, _param_send_data_cb);
//  //    ev::stop(_write_io, _loop);
//  //  }
//}

//void stream::enable_send_cb() {
//  //  if (_send_data_dup_cb) {
//  //    swap(_send_data_dup_cb, _send_data_cb);
//  //    swap(_param_send_data_dup_cb, _param_send_data_cb);
//  //    ev::start(_write_io, _loop);
//  //  }
//}

//void stream::cleanup() {
//  tcp::stream::cleanup();
//  stop_events();
//}

//} // namespace bro::net::udp::send
