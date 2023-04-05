#include <network/platforms/system.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <string.h>
#ifdef WITH_SCTP
#include <netinet/sctp.h>
#endif
namespace bro::net {

std::string fill_error(char const *const err) {
  if (errno) {
    std::string status(err);
    status = status + ", errno - " + strerror(errno);
    errno = 0;
    return status;
  }
  return err;
}

std::string fill_error(std::string const &err) {
  if (errno) {
    std::string status(err);
    status = status + ", errno - " + strerror(errno);
    errno = 0;
    return status;
  }
  return err;
}

void append_error(std::string &to, std::string const &new_err) {
  if (!to.empty())
    to += "; " + fill_error(new_err);
  else
    to = fill_error(new_err);
}

void append_error(std::string &to, char const *const new_err) {
  if (!to.empty())
    to += "; " + fill_error(new_err);
  else
    to = fill_error(new_err);
}

bool set_tcp_options(int file_descr, std::string &err) {
#if defined __linux__ && defined TCP_NODELAY
  /* Set the NODELAY option */
  int optval = 1;
  if (0 != ::setsockopt(file_descr, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char const *>(&optval), sizeof(optval))) {
    append_error(err, "set tcp no delay failed");
    errno = 0;
    return false;
  }
#endif // TCP_NODELAY
  return true;
}

bool is_connection_established(int file_descr, std::string &err) {
  int optval = -1;
  socklen_t optlen = sizeof(optval);
  int rc = getsockopt(file_descr, SOL_SOCKET, SO_ERROR, &optval, &optlen);

  if (0 != rc) {
    append_error(err, "getsockopt error");
    return false;
  }
  if (0 != optval) {
    append_error(err, "connection not established");
    return false;
  }
  return true;
}

std::optional<proto::ip::full_address> get_address_from_file_descr(proto::ip::address::version ver, int file_descr) {
  switch (ver) {
  case proto::ip::address::version::e_v4: {
    struct sockaddr_in t_local_addr = {0, 0, {0}, {0}};
    socklen_t addrlen = sizeof(t_local_addr);
    if (0 == getsockname(file_descr, (struct sockaddr *) &t_local_addr, &addrlen))
      return proto::ip::full_address(t_local_addr);
    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 t_local_addr = {0, 0, 0, {{{0}}}, 0};
    socklen_t addrlen = sizeof(t_local_addr);
    if (0 == getsockname(file_descr, (struct sockaddr *) &t_local_addr, &addrlen))
      return proto::ip::full_address(t_local_addr);
    break;
  }
  case proto::ip::address::version::e_none:
    break;
  }
  return std::nullopt;
}

proto::ip::full_address get_address_from_file_descr(proto::ip::address::version ver, int file_descr, std::string &err) {
  switch (ver) {
  case proto::ip::address::version::e_v4: {
    struct sockaddr_in t_local_addr = {0, 0, {0}, {0}};
    socklen_t addrlen = sizeof(t_local_addr);
    if (0 == getsockname(file_descr, (struct sockaddr *) &t_local_addr, &addrlen))
      return proto::ip::full_address(t_local_addr);
    append_error(err, "couldn't get address from file descriptor(ipv4)");
    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 t_local_addr = {0, 0, 0, {{{0}}}, 0};
    socklen_t addrlen = sizeof(t_local_addr);
    if (0 == getsockname(file_descr, (struct sockaddr *) &t_local_addr, &addrlen))
      return proto::ip::full_address(t_local_addr);
    append_error(err, "couldn't get address from file descriptor(ipv6)");
    break;
  }
  case proto::ip::address::version::e_none: {
    append_error(err, "incorrect address type");
    break;
  }
  }
  return {};
}

bool bind_on_address(proto::ip::full_address &self_address, int file_descr, std::string &err) {
  switch (self_address.get_address().get_version()) {
  case proto::ip::address::version::e_v4: {
    sockaddr_in local_addr = self_address.to_native_v4();
    if (0 == ::bind(file_descr, reinterpret_cast<sockaddr *>(&local_addr), sizeof(struct sockaddr_in)))
      return true;
    append_error(err, "couldn't bind on address - " + self_address.to_string());
    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 local_addr = self_address.to_native_v6();
    if (0 == ::bind(file_descr, reinterpret_cast<sockaddr *>(&local_addr), sizeof(local_addr)))
      return true;
    append_error(err, "couldn't bind on address - " + self_address.to_string());
    break;
  }
  default:
    append_error(err, "incorrect self address pass to function bind_on_address");
    break;
  }
  return false;
}

#ifdef WITH_SCTP
bool bind_on_sctp_address(proto::ip::full_address &self_address, int file_descr, std::string &err) {
  switch (self_address.get_address().get_version()) {
  case proto::ip::address::version::e_v4: {
    sockaddr_in local_addr = self_address.to_native_v4();
    if (0 == sctp_bindx(file_descr, reinterpret_cast<sockaddr *>(&local_addr), 1, SCTP_BINDX_ADD_ADDR))
      return true;
    append_error(err, "couldn't bind on sctp address - " + self_address.to_string());
    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 local_addr = self_address.to_native_v6();
    if (0 == sctp_bindx(file_descr, reinterpret_cast<sockaddr *>(&local_addr), 1, SCTP_BINDX_ADD_ADDR))
      return true;
    append_error(err, "couldn't bind on sctp address - " + self_address.to_string());
    break;
  }
  default:
    append_error(err, "incorrect self address pass to function bind_on_address");
    break;
  }
  return false;
}

bool asconf_on(int /*file_descr*/, std::string & /*err*/) {
#ifdef SCTP_AUTO_ASCONF
//  int optval = 1;
//  if (setsockopt(file_descr, IPPROTO_SCTP, SCTP_AUTO_ASCONF, &optval, sizeof(optval)) < 0) {
//    err.append(std::string("couldn't set option asconf for sctp, errno - ") + strerror(errno));
//    return false;
//  }
#endif /* SCTP_AUTO_ASCONF */
  return true;
}

bool connect_sctp_streams(proto::ip::full_address const &peer_addr, int file_descr, std::string &err) {
  int rc = -1;
  switch (peer_addr.get_address().get_version()) {
  case proto::ip::address::version::e_v4: {
    sockaddr_in addr = peer_addr.to_native_v4();
    rc = sctp_connectx(file_descr, reinterpret_cast<sockaddr *>(&addr), 1, nullptr);
    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 addr = peer_addr.to_native_v6();
    rc = sctp_connectx(file_descr, reinterpret_cast<sockaddr *>(&addr), 1, nullptr);
    break;
  }
  default: {
    append_error(err, "incorrect peer address");
    return false;
  }
  }
  if (0 == rc || EINPROGRESS == errno)
    return true;

  append_error(err, "coulnd't connect to sctp server - " + peer_addr.to_string());
  return false;
}

bool set_sctp_options(proto::ip::address::version ver,
                      bro::net::sctp::settings *settings,
                      int file_descr,
                      std::string &err) {
  /* Set the NODELAY option (Nagle-like algorithm) */

/* Set the association parameters: max number of retransmits, ... */
#ifdef SCTP_ASSOCINFO
  struct sctp_assocparams assoc;
  memset(&assoc, 0, sizeof(assoc));
  assoc.sasoc_asocmaxrxt = settings->_sasoc_asocmaxrxt; /* Maximum number of retransmission attempts:
                                    we want fast detection of errors */
  /* Note that this must remain less than the sum of retransmission parameters
   * of the different paths. */
  if (-1 == setsockopt(file_descr, IPPROTO_SCTP, SCTP_ASSOCINFO, &assoc, sizeof(assoc))) {
    append_error(err, "coulnd't set sctp maximum number of retransmit");
    return false;
  }
#endif // SCTP_ASSOCINFO

/* Set the INIT parameters, such as number of streams */
#ifdef SCTP_INITMSG
  struct sctp_initmsg init;
  memset(&init, 0, sizeof(init));
  /* Set the init options -- need to receive SCTP_COMM_UP to confirm the
   * requested parameters, but we don't care (best effort) */
  init.sinit_num_ostreams = settings->_sinit_num_ostreams; /* desired number of outgoing streams */
  init.sinit_max_init_timeo = settings->_sinit_max_init_timeo;
  init.sinit_max_attempts = settings->_sinit_max_attempts;
  init.sinit_max_instreams = settings->_sinit_num_istreams;
  if (-1 == setsockopt(file_descr, IPPROTO_SCTP, SCTP_INITMSG, &init, sizeof(init))) {
    append_error(err, "coulnd't set sctp init message parameters");
    return false;
  }
#endif // SCTP_INITMSG

/* The SO_LINGER option will be reset if we want to perform SCTP ABORT */
#ifdef SO_LINGER
  if (settings->_reset_linger) {
    struct linger linger;
    memset(&linger, 0, sizeof(linger));
    linger.l_onoff = 0;  /* Do not activate the linger */
    linger.l_linger = 0; /* Ignored, but it would mean : Return immediately when closing (=>
              abort) (graceful shutdown in background) */
    if (-1 == setsockopt(file_descr, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger))) {
      append_error(err, "coulnd't set sctp so linger option");
      return false;
    }
  }
#endif // SO_LINGER

  if (settings->_use_mapped_v4_address) {
    if (proto::ip::address::version::e_v6 == ver) {
      int v4mapped{0};
      //            v4mapped = 1;	/* but we may have to, otherwise the
      //            bind fails in some environments */
      ;
      if (-1 == setsockopt(file_descr, IPPROTO_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR, &v4mapped, sizeof(v4mapped))) {
        append_error(err, "coulnd't enable mapped if v4 address for sctp");
        return false;
      }
    }
  }

#ifdef SCTP_EVENTS

  struct sctp_event_subscribe event;
  memset(&event, 0, sizeof(event));
  event.sctp_data_io_event = settings->_sctp_data_io_event;                   /* to receive the stream ID in SCTP_SNDRCV
                                                                                ancilliary data on message reception */
  event.sctp_association_event = settings->_sctp_association_event;           /* new or closed associations (mostly for
                                                                               one-to-many style sockets) */
  event.sctp_address_event = settings->_sctp_address_event;                   /* address changes */
  event.sctp_send_failure_event = settings->_sctp_send_failure_event;         /* delivery failures */
  event.sctp_peer_error_event = settings->_sctp_peer_error_event;             /* remote peer sends an error */
  event.sctp_shutdown_event = settings->_sctp_shutdown_event;                 /* peer has sent a SHUTDOWN */
  event.sctp_partial_delivery_event = settings->_sctp_partial_delivery_event; /* a partial delivery is aborted,
                                                                                 probably indicating the
                                                                                 connection is being shutdown */
  event.sctp_adaptation_layer_event = settings->_sctp_adaptation_layer_event; /* adaptation layer notifications */
  event.sctp_authentication_event = settings->_sctp_authentication_event;     /* when new key is made active */

  if (-1 == setsockopt(file_descr, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event))) {
    append_error(err, "coulnd't enable sctp events");
    return false;
  }

#endif // SCTP_EVENTS

///* Set the SCTP_DISABLE_FRAGMENTS option, required for TLS */
#ifdef SCTP_DISABLE_FRAGMENTS
  if (settings->_disable_frag) {
    int nofrag = 0;
    /* We turn ON the fragmentation, since Diameter  messages & TLS messages can be quite large. */
    if (-1 == setsockopt(file_descr, IPPROTO_SCTP, SCTP_DISABLE_FRAGMENTS, &nofrag, sizeof(nofrag))) {
      append_error(err, "coulnd't enable fragmentation for sctp messages");
      return false;
    }
  }
#endif // SCTP_DISABLE_FRAGMENTS

/* SCTP_PEER_ADDR_PARAMS	control heartbeat per peer address. We set it as
 * a default for all addresses in the association; not sure if it works ... */
#ifdef SCTP_PEER_ADDR_PARAMS
  if (settings->_enable_heart_beats) {
    struct sctp_paddrparams parms;
    memset(&parms, 0, sizeof(parms));
    parms.spp_address.ss_family = AF_INET;
    parms.spp_flags = SPP_HB_ENABLE; /* Enable heartbeat for the association */
#ifdef SPP_PMTUD_ENABLE
    parms.spp_flags |= SPP_PMTUD_ENABLE;              /* also enable path MTU discovery mechanism */
#endif                                                /* SPP_PMTUD_ENABLE */
    parms.spp_hbinterval = settings->_spp_hbinterval; /* Send an heartbeat every 6 seconds to quickly
                                                           start retransmissions */
    /* parms.spp_pathmaxrxt : max nbr of restransmissions on this address. There
         * is a relationship with sasoc_asocmaxrxt, so we leave the default here */

    /* Set the option to the socket */
    if (-1 == setsockopt(file_descr, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &parms, sizeof(parms))) {
      append_error(err, "coulnd't enable sctp heart beats");
      return false;
    };

#endif // SCTP_PEER_ADDR_PARAMS
  }

  return true;
}

#endif // WITH_SCTP

bool connect_stream(proto::ip::full_address const &peer_addr, int file_descr, std::string &err) {
  int rc = -1;
  switch (peer_addr.get_address().get_version()) {
  case proto::ip::address::version::e_v4: {
    sockaddr_in addr = peer_addr.to_native_v4();
    rc = ::connect(file_descr, reinterpret_cast<struct sockaddr *>(&addr), sizeof(peer_addr));
    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 addr = peer_addr.to_native_v6();
    rc = ::connect(file_descr, reinterpret_cast<struct sockaddr *>(&addr), sizeof(peer_addr));
    break;
  }
  default: {
    append_error(err, "incorrect peer address");
    return false;
  }
  }
  if (0 == rc || EINPROGRESS == errno)
    return true;
  append_error(err, "coulnd't connect to server - " + peer_addr.to_string());
  return false;
}

bool reuse_address(int file_descr, std::string &err) {
  int reuseaddr = 1;
  if (-1 == setsockopt(file_descr, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<void const *>(&reuseaddr), sizeof(int))) {
    append_error(err, "couldn't reuse address");
    return false;
  }
  return true;
}

bool start_listen(int file_descr, int listen_backlog, std::string &err) {
  if (0 != ::listen(file_descr, listen_backlog)) {
    append_error(err, "server listen is failed");
    return false;
  }
  return true;
}

bool set_non_blocking_mode(int file_descr, std::string &err) {
#ifdef FIONBIO
  int mode = 1;
  if (-1 == ioctl(file_descr, FIONBIO, &mode)) {
    append_error(err, "coulnd't set non blocking mode for socket");
    return false;
  }
#endif // FIONBIO
  return true;
}

bool set_socket_buffer_size(int file_descr, int buffer_size, std::string &err) {
#ifdef SO_SNDBUF
  if (-1
      == setsockopt(file_descr,
                    SOL_SOCKET,
                    SO_SNDBUF,
                    reinterpret_cast<char const *>(&buffer_size),
                    sizeof(buffer_size))) {
    append_error(err, "coulnd't set send buffer size");
    return false;
  }
#endif // SO_SNDBUF
#ifdef SO_RCVBUF
  if (-1
      == setsockopt(file_descr,
                    SOL_SOCKET,
                    SO_RCVBUF,
                    reinterpret_cast<char const *>(&buffer_size),
                    sizeof(buffer_size))) {
    append_error(err, "coulnd't set receive buffer size");
    return false;
  }
#endif // SO_RCVBUF
  return true;
}

std::optional<int> create_socket(proto::ip::address::version ver, socket_type s_type, std::string &err) {
  int af_type = proto::ip::address::version::e_v6 == ver ? AF_INET6 : AF_INET;
  int protocol = 0;
  int type = 0;
  switch (s_type) {
  case socket_type::e_tcp:
    protocol = IPPROTO_TCP;
    type = SOCK_STREAM;
    break;
  case socket_type::e_sctp:
    protocol = IPPROTO_SCTP;
    type = SOCK_STREAM;
    break;
  case socket_type::e_udp:
    protocol = IPPROTO_UDP;
    type = SOCK_DGRAM;
    break;
  default:
    append_error(err, "incorrect socket type");
    return std::nullopt;
  }

  int file_des = ::socket(af_type, type, protocol);
  if (-1 == file_des) {
    append_error(err, "coulnd't create socket");
    return std::nullopt;
  }
  return file_des;
}

bool close_socket(int &file_descr, std::string &err) {
  bool res = true;
  if (-1 != file_descr) {
    if (-1 == ::close(file_descr)) {
      res = false;
      append_error(err, "close socket return an error");
    }
    file_descr = -1;
  }
  return res;
}

accept_connection_res accept_connection(proto::ip::address::version ver, int server_fd, std::string &err) {
  accept_connection_details res;
  res._client_fd = -1;
  switch (ver) {
  case proto::ip::address::version::e_v4: {
    struct sockaddr_in t_peer_addr = {0, 0, {0}, {0}};
    socklen_t addrlen = sizeof(t_peer_addr);
    while (true) {
      res._client_fd = accept(server_fd, (struct sockaddr *) (&t_peer_addr), &addrlen);
      if (-1 == res._client_fd) {
        if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno)
          break;
      } else
        break;
    }

    if (-1 != res._client_fd)
      res._peer_addr = proto::ip::full_address(t_peer_addr);
    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 t_peer_addr = {0, 0, 0, {{{0}}}, 0};
    socklen_t addrlen = sizeof(t_peer_addr);
    while (true) {
      res._client_fd = accept(server_fd, (struct sockaddr *) (&t_peer_addr), &addrlen);
      if (-1 == res._client_fd) {
        if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno)
          break;
      } else
        break;
    }
    if (-1 != res._client_fd)
      res._peer_addr = proto::ip::full_address(t_peer_addr);
    break;
  }
  default:
    break;
  }
  if (-1 != res._client_fd) {
    if (auto addr = get_address_from_file_descr(ver, res._client_fd); addr) // NOTE: actualy it never fails
      res._self_address = *addr;
    return res;
  } else
    append_error(err, "coulnd't accept connection");
  return std::nullopt;
}

} // namespace bro::net
