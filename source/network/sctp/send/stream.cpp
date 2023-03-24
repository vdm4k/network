#include "network/common.h"
#include <netinet/sctp.h>
#include <network/libev/libev.h>
#include <network/sctp/send/stream.h>

namespace bro::net::sctp::send {

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

void stream::init_config(settings *send_params) { _settings = *send_params; }

bool stream::init(settings *send_params) {
  init_config(send_params);
  bool res = create_socket(_settings._peer_addr.get_address().get_version(),
                           type::e_sctp) &&
             connect();
  if (res) {
    set_connection_state(state::e_wait);
  } else {
    cleanup();
  }
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
  if (_send_data_cb)
    ev::start(_write_io, _loop);
  ev::start(_read_io, _loop);
  set_connection_state(state::e_established);
}

ssize_t stream::send(std::byte *data, size_t data_size) {
  ssize_t sent{0};
  sctp_sndrcvinfo sinfo{0,
                        0,
                        uint16_t(_settings._unordered ? SCTP_UNORDERED : 0),
                        htonl(_settings._ppid),
                        0,
                        0,
                        0,
                        0,
                        0};
  while (true) {
    sent = sctp_send(_file_descr, data, data_size, &sinfo, MSG_NOSIGNAL);
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
  sctp_sndrcvinfo sinfo{0,
                        0,
                        uint16_t(_settings._unordered ? SCTP_UNORDERED : 0),
                        htonl(_settings._ppid),
                        0,
                        0,
                        0,
                        0,
                        0};
  ssize_t rec{-1};
  while (true) {
    int msg_flags = MSG_NOSIGNAL;
    rec = sctp_recvmsg(_file_descr, buffer, buffer_size, nullptr, 0, &sinfo,
                       &msg_flags);
    if (msg_flags & MSG_NOTIFICATION) {
      union sctp_notification *notif = (union sctp_notification *)buffer;
      switch (notif->sn_header.sn_type) {
      //  The attached datagram could not be sent
      //  to the remote endpoint.  This structure includes the original
      //  SCTP_SNDINFO that was used in sending this message
      case SCTP_SEND_FAILED: {
        set_detailed_error("receive send failed notification");
        set_connection_state(state::e_failed);
        break; // error
      }
      //  The peer has sent a SHUTDOWN.  No further
      //  data should be sent on this socket.
      case SCTP_SHUTDOWN_EVENT: {
        set_detailed_error("receive shutdown notification");
        set_connection_state(state::e_failed);
        break; // error
      }
      //  This notification is used to tell a
      //  receiver that the partial delivery has been aborted.  This may
      //  indicate that the association is about to be aborted.
      case SCTP_PARTIAL_DELIVERY_EVENT: {
        set_detailed_error("receive partial delivery notification");
        set_connection_state(state::e_failed);
        break; // error
      }
      // This notification is used to tell a
      // receiver that either an error occurred on
      // authentication, or a new key was made active.
      // same as SCTP_AUTHENTICATION_INDICATION
      case SCTP_AUTHENTICATION_EVENT:
        break;
      // This tag indicates that an association has
      // either been opened or closed.  Refer to Section 6.1.1 for details.
      // Communication notifications inform the ULP that an SCTP
      // association has either begun or ended. The identifier for a new
      // association is provided by this notification.
      case SCTP_ASSOC_CHANGE:
        break;

      // This tag indicates that an address that is
      // part of an existing association has experienced a change of
      // state (e.g., a failure or return to service of the reachability
      // of an endpoint via a specific transport address).
      // When a destination address on a multi-homed peer encounters a
      // change an interface details event is sent.
      case SCTP_PEER_ADDR_CHANGE:
        break;

      // The attached error message is an Operation
      // Error message received from the remote peer.  It includes the
      // complete TLV sent by the remote endpoint.
      // A remote peer may send an Operational Error message to its peer.
      // This message indicates a variety of error conditions on an
      // association. The entire error TLV as it appears on the wire is
      // included in a SCTP_REMOTE_ERROR event.
      case SCTP_REMOTE_ERROR:
        break;
        // This notification holds the peer's indicated adaptation layer

      case SCTP_ADAPTATION_INDICATION:
        break;

      // When the SCTP stack has no more user data to send or
      // retransmit, this notification is given to the user. Also, at
      // the time when a user app subscribes to this event, if there
      // is no data to be sent or retransmit, the stack will
      // immediately send up this notification.
      case SCTP_SENDER_DRY_EVENT:
        break;
      }
      return is_active() ? 0 : -1;
    }

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
  if (connect_sctp_streams(_settings._peer_addr, _file_descr,
                           get_detailed_error()))
    return true;
  set_connection_state(state::e_failed);
  return false;
}

void stream::set_received_data_cb(strm::received_data_cb cb,
                                  std::any user_data) {
  _received_data_cb = cb;
  _param_received_data_cb = user_data;
}

void stream::set_send_data_cb(strm::send_data_cb cb, std::any user_data) {
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
  if (_received_data_cb)
    _received_data_cb(this, _param_received_data_cb);
}

void stream::send_data() {
  if (_send_data_cb)
    _send_data_cb(this, _param_send_data_cb);
}

void stream::cleanup() {
  sctp::stream::cleanup();
  stop_events();
}

} // namespace bro::net::sctp::send
