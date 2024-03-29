#include <network/stream/listen/settings.h>
#include <network/stream/listen/stream.h>
#include <network/stream/send/settings.h>

namespace bro::net::listen {

stream::~stream() {
  stream::cleanup();
}

ssize_t stream::send(std::byte const * /*data*/, size_t /*data_size*/) {
  set_detailed_error("couldn't send data by listen stream");
  return -1;
}

ssize_t stream::receive(std::byte * /*data*/, size_t /*data_size*/) {
  set_detailed_error("couldn't receive data in listen stream");
  return -1;
}

void stream::set_received_data_cb(strm::received_data_cb /*cb*/, std::any /*param*/) {}
void stream::set_send_data_cb(strm::received_data_cb /*cb*/, std::any /*param*/) {}

bool stream::is_active() const {
  return get_state() == state::e_wait;
}

bool stream::fill_send_stream(accept_connection_res const &result, std::unique_ptr<net::stream> &new_stream) {
  auto *n_stream = (bro::net::stream *) (new_stream.get());
  if (!result) {
    _statistic._failed_to_accept_connections++;
    n_stream->set_connection_state(state::e_failed);
    return false;
  }

  auto *set = (bro::net::send::settings *) new_stream->get_settings();
  set->_peer_addr = result->_peer_addr;
  set->_self_addr = result->_self_address;
  n_stream->_file_descr = result->_client_fd;
  if (!n_stream->set_socket_options()) {
    _statistic._failed_to_accept_connections++;
    return false;
  }
  _statistic._success_accept_connections++;
  n_stream->set_connection_state(state::e_established);
  return true;
}

void stream::handle_incoming_connection() {
  auto *set = (bro::net::listen::settings *) get_settings();
  if (!set->_proc_in_conn)
    return;
  auto addr_t = set->_listen_address.get_address().get_version();
  auto sck{generate_send_stream()};
  (void) fill_send_stream(accept_connection(addr_t, _file_descr, sck->get_error_description()), sck);
  set->_proc_in_conn(std::move(sck), set->_in_conn_handler_data);
}

void stream::assign_event(bro::ev::io_t &&in_conn) {
  _in_connections = std::move(in_conn);
  _in_connections->start(get_fd(), std::function<void()>(std::bind(&stream::handle_incoming_connection, this)));
}

void stream::cleanup() {
  if (_in_connections)
    _in_connections->stop();
  net::stream::cleanup();
}

void stream::reset_statistic() {
  _statistic.reset();
}

} // namespace bro::net::listen
