#include "network/platforms/system.h"
#include <netinet/sctp.h>
#include <network/sctp/send/stream.h>

namespace bro::net::sctp::send {

stream::~stream() {
  cleanup();
}

bool stream::init(settings *send_params) {
  _settings = *send_params;
  bool res = create_socket(_settings._peer_addr.get_address().get_version(), socket_type::e_sctp) && connect();
  if (res) {
    set_connection_state(state::e_wait);
  } else {
    cleanup();
  }
  return res;
}

ssize_t stream::send_data(std::byte const *data, size_t data_size, bool /*resend*/) {
  ssize_t sent{0};
  sctp_sndrcvinfo sinfo{0, 0, uint16_t(_settings._unordered ? SCTP_UNORDERED : 0), htonl(_settings._ppid), 0, 0, 0, 0, 0};
  while (true) {
    sent = sctp_send(get_fd(), data, data_size, &sinfo, MSG_NOSIGNAL);

    if (sent > 0) {
      ++_statistic._success_send_data;
      break;
    }

    if (EAGAIN == errno || EWOULDBLOCK == errno || EINTR == errno) {
      errno = 0;
      ++_statistic._retry_send_data;
      continue;
    }

    // 0 may also be returned if the requested number of bytes to receive from a stream socket was 0
    if (data_size == 0 && sent == 0)
      break;

    set_detailed_error("send return error");
    set_connection_state(state::e_failed);
    sent = -1;
    break;
  }
  return sent;
}

ssize_t stream::receive(std::byte *buffer, size_t buffer_size) {
  sctp_sndrcvinfo sinfo{0, 0, uint16_t(_settings._unordered ? SCTP_UNORDERED : 0), htonl(_settings._ppid), 0, 0, 0, 0, 0};
  ssize_t rec{-1};
  while (true) {
    int msg_flags = MSG_NOSIGNAL;
    rec = sctp_recvmsg(get_fd(), buffer, buffer_size, nullptr, 0, &sinfo, &msg_flags);
    if (msg_flags & MSG_NOTIFICATION) {
      rec = is_sctp_flags_ok(buffer) ? 0 : -1;
      break;
    }

    if (rec > 0) {
      ++_statistic._success_recv_data;
      break;
    }

    if (EAGAIN == errno || EWOULDBLOCK == errno || EINTR == errno) {
      errno = 0;
      ++_statistic._retry_recv_data;
      continue;
    }

    // 0 may also be returned if the requested number of bytes to receive from a stream socket was 0
    if (buffer_size == 0 && rec == 0)
      break;

    set_detailed_error("recv return error");
    set_connection_state(state::e_failed);
    ++_statistic._failed_recv_data;
    rec = -1;
    break;
  }
  return rec;
}

bool stream::connect() {
  if (connect_sctp_streams(get_settings()->_peer_addr, get_fd(), get_detailed_error()))
    return true;
  set_connection_state(state::e_failed);
  return false;
}

void stream::reset_statistic() {
  _statistic.reset();
}

void stream::cleanup() {
  net::send::stream::cleanup();
}

bool stream::is_sctp_flags_ok(std::byte *buffer) {
  union sctp_notification *notif = (union sctp_notification *) buffer;
  switch (notif->sn_header.sn_type) {
  //  The attached datagram could not be sent
  //  to the remote endpoint.  This structure includes the original
  //  SCTP_SNDINFO that was used in sending this message
  case SCTP_SEND_FAILED: {
    set_detailed_error("receive send failed notification");
    set_connection_state(state::e_failed);
    return false; // error
  }
  //  The peer has sent a SHUTDOWN.  No further
  //  data should be sent on this socket.
  case SCTP_SHUTDOWN_EVENT: {
    set_detailed_error("receive shutdown notification");
    set_connection_state(state::e_failed);
    return false; // error
  }
  //  This notification is used to tell a
  //  receiver that the partial delivery has been aborted.  This may
  //  indicate that the association is about to be aborted.
  case SCTP_PARTIAL_DELIVERY_EVENT: {
    set_detailed_error("receive partial delivery notification");
    set_connection_state(state::e_failed);
    return false; // error
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
  return true;
}

bool stream::create_socket(proto::ip::address::version version, socket_type s_type) {
  if (!net::stream::create_socket(version, s_type)) {
    return false;
  }
  if (!set_sctp_options(version, (settings *) get_settings(), get_fd(), get_detailed_error())) {
    cleanup();
    return false;
  }
  return true;
}

} // namespace bro::net::sctp::send
