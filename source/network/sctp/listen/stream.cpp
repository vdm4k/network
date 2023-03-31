#include <network/libev/libev.h>
#include <network/sctp/listen/stream.h>
#include <network/sctp/send/stream.h>

#include "network/common.h"

namespace bro::net::sctp::listen {

void incoming_connection_cb(struct ev_loop * /*loop*/, ev_io *w, int /*revents*/) {
  auto *conn = reinterpret_cast<stream *>(w->data);
  conn->handle_incoming_connection(accept_connection(conn->get_self_address().get_address().get_version(), w->fd));
}

stream::~stream() {
  cleanup();
}

ssize_t stream::send(std::byte const * /*data*/, size_t /*data_size*/) {
  set_detailed_error("couldn't send data by listen stream");
  return 0;
}

ssize_t stream::receive(std::byte * /*data*/, size_t /*data_size*/) {
  set_detailed_error("couldn't receive data in listen stream");
  return 0;
}

void stream::set_received_data_cb(strm::received_data_cb /*cb*/, std::any /*param*/) {}

bool stream::is_active() const {
  return get_state() == state::e_wait;
}

void stream::reset_statistic() {
  _statistic._success_accept_connections = 0;
  _statistic._failed_to_accept_connections = 0;
}

bool stream::create_listen_socket() {
  return create_socket(_settings._listen_address.get_address().get_version(), type::e_sctp)
         && reuse_address(_file_descr, get_detailed_error())
         && bind_on_sctp_address(_settings._listen_address, _file_descr, get_detailed_error())
         && asconf_on(_file_descr, get_detailed_error())
         && start_listen(_file_descr, _settings._listen_backlog, get_detailed_error());
}

bool stream::fill_send_stream(accept_connection_res const &result, std::unique_ptr<send::stream> &sck) {
  if (!result) {
    _statistic._failed_to_accept_connections++;
    sck->set_connection_state(state::e_failed);
    sck->set_detailed_error("couldn't accept new incomming connection");
    return false;
  }

  _statistic._success_accept_connections++;
  sck->current_settings()->_peer_addr = result->_peer_addr;
  sck->current_settings()->_self_addr = result->_self_address;
  sck->current_settings()->_ppid = _settings._ppid;
  sck->_file_descr = result->_client_fd;
  if (!sck->set_socket_options() || !sck->set_socket_specific_options(result->_peer_addr.get_address().get_version()))
    return false;
  sck->set_connection_state(state::e_established);
  return true;
}

std::unique_ptr<send::stream> stream::generate_send_stream() {
  return std::make_unique<send::stream>();
}

void stream::handle_incoming_connection(accept_connection_res const &result) {
  auto sck{generate_send_stream()};
  (void) fill_send_stream(result, sck);
  if (_settings._proc_in_conn)
    _settings._proc_in_conn(std::move(sck), _settings._in_conn_handler_data);
}

void stream::assign_loop(struct ev_loop *loop) {
  _loop = loop;
  ev::init(_connect_io, incoming_connection_cb, _file_descr, EV_READ, this);
  ev::start(_connect_io, _loop);
}

proto::ip::full_address const &stream::get_self_address() const {
  return _settings._listen_address;
}

bool stream::init(settings *listen_params) {
  bool res{false};
  _settings = *listen_params;
  if (create_listen_socket()) {
    set_connection_state(state::e_wait);
    res = true;
  } else {
    set_connection_state(state::e_failed);
    cleanup();
  }
  return res;
}

void stream::cleanup() {
  sctp::stream::cleanup();
  ev::stop(_connect_io, _loop);
}

} // namespace bro::net::sctp::listen
