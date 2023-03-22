#include <network/common.h>
#include <network/stream.h>
#include <string.h>

#ifdef WITH_SCTP
#include <netinet/sctp.h>
#endif
namespace bro::net {

proto::ip::full_address get_local_address(proto::ip::address::version ver,
                                          int fd) {
  if (ver == proto::ip::address::version::e_v4) {
    struct sockaddr_in t_local_addr = {0, 0, {0}, {0}};
    socklen_t addrlen = sizeof(t_local_addr);
    getsockname(fd, (struct sockaddr *)&t_local_addr, &addrlen);
    return proto::ip::full_address(t_local_addr);
  }
  sockaddr_in6 t_local_addr = {0, 0, 0, {{{0}}}, 0};
  socklen_t addrlen = sizeof(t_local_addr);
  getsockname(fd, (struct sockaddr *)&t_local_addr, &addrlen);
  return proto::ip::full_address(t_local_addr);
}

bool fill_sockaddr(proto::ip::full_address const &ipaddr, sockaddr_in &addr,
                   std::string &detailed_error) {
  switch (ipaddr.get_address().get_version()) {
  case proto::ip::address::version::e_v4: {
    addr = ipaddr.to_native_v4();
    return true;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 local_addr = ipaddr.to_native_v6();
    auto *p_addr = reinterpret_cast<sockaddr_in6 *>(&addr);
    *p_addr = local_addr;
    return true;
  }
  default: {
    detailed_error = "incorrect address type";
    break;
  }
  }
  return false;
}

bool bind_on_address(proto::ip::full_address &self_address, int file_descr,
                     std::string &detailed_error) {
  switch (self_address.get_address().get_version()) {
  case proto::ip::address::version::e_v4: {
    sockaddr_in local_addr = self_address.to_native_v4();
    if (0 == ::bind(file_descr, reinterpret_cast<sockaddr *>(&local_addr),
                    sizeof(local_addr)))
      return true;
    detailed_error.append("couldn't bind on address - " +
                          self_address.to_string() + ", errno - " +
                          strerror(errno));

    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 local_addr = self_address.to_native_v6();
    if (0 == ::bind(file_descr, reinterpret_cast<sockaddr *>(&local_addr),
                    sizeof(local_addr)))
      return true;
    detailed_error.append("couldn't bind on address - " +
                          self_address.to_string() + ", errno - " +
                          strerror(errno));

    break;
  }
  default:
    detailed_error.append(
        "incorrect self address pass to function bind_on_address");
    break;
  }
  return false;
}

#ifdef WITH_SCTP
bool bind_on_sctp_address(proto::ip::full_address &self_address, int file_descr,
                          std::string &detailed_error) {
  switch (self_address.get_address().get_version()) {
  case proto::ip::address::version::e_v4: {
    sockaddr_in local_addr = self_address.to_native_v4();
    if (0 == sctp_bindx(file_descr, reinterpret_cast<sockaddr *>(&local_addr),
                        1, SCTP_BINDX_ADD_ADDR))
      return true;
    detailed_error.append("couldn't bind sctp on address - " +
                          self_address.to_string() + ", errno - " +
                          strerror(errno));

    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 local_addr = self_address.to_native_v6();
    if (0 == sctp_bindx(file_descr, reinterpret_cast<sockaddr *>(&local_addr),
                        1, SCTP_BINDX_ADD_ADDR))
      return true;
    detailed_error.append("couldn't bind sctp on address - " +
                          self_address.to_string() + ", errno - " +
                          strerror(errno));

    break;
  }
  default:
    detailed_error.append(
        "incorrect self address pass to function bind_on_address");
    break;
  }
  return false;
}

bool asconf_on(int file_descr, std::string & /*detailed_error*/) {

#ifdef SCTP_AUTO_ASCONF
  int asconf = 1; /* allow automatic use of added or removed addresses in the
                     association (for bound-all sockets) */
  if (-1 == setsockopt(file_descr, IPPROTO_SCTP, SCTP_AUTO_ASCONF, &asconf,
                       sizeof(asconf))) {
    // TODO: maybe not so important
    //     detailed_error.append(
    //         std::string("couldn't set option SO_REUSEADDR, errno - ") +
    //         strerror(errno));
    //     return false;
  }
#endif /* SCTP_AUTO_ASCONF */
  return true;
}

bool connect_sctp_streams(proto::ip::full_address const &peer_addr,
                          int file_descr, std::string &detailed_error) {
  int rc = -1;
  switch (peer_addr.get_address().get_version()) {
  case proto::ip::address::version::e_v4: {
    sockaddr_in addr = peer_addr.to_native_v4();
    rc = sctp_connectx(file_descr, reinterpret_cast<sockaddr *>(&addr), 1,
                       nullptr);
    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 addr = peer_addr.to_native_v6();
    rc = sctp_connectx(file_descr, reinterpret_cast<sockaddr *>(&addr), 1,
                       nullptr);
    break;
  }
  default: {
    detailed_error.append("incorrect peer address");
    return false;
  }
  }
  if (0 == rc || EINPROGRESS == errno)
    return true;
  detailed_error.append("coulnd't connect to server - " +
                        peer_addr.to_string() + ", errno - " + strerror(errno));

  return false;
}

#endif

bool connect_stream(const proto::ip::full_address &peer_addr, int file_descr,
                    std::string &detailed_error) {

  int rc = -1;
  switch (peer_addr.get_address().get_version()) {
  case proto::ip::address::version::e_v4: {
    sockaddr_in addr = peer_addr.to_native_v4();
    rc = ::connect(file_descr, reinterpret_cast<struct sockaddr *>(&addr),
                   sizeof(peer_addr));
    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 addr = peer_addr.to_native_v6();
    rc = ::connect(file_descr, reinterpret_cast<struct sockaddr *>(&addr),
                   sizeof(peer_addr));
    break;
  }
  default: {
    detailed_error.append("incorrect peer address");
    return false;
  }
  }
  if (0 == rc || EINPROGRESS == errno)
    return true;
  detailed_error.append("coulnd't connect to server - " +
                        peer_addr.to_string() + ", errno - " + strerror(errno));

  return false;
}

bool reuse_address(int file_descr, std::string &detailed_error) {

  int reuseaddr = 1;
  if (-1 == setsockopt(file_descr, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const void *>(&reuseaddr),
                       sizeof(int))) {
    detailed_error.append(
        std::string("couldn't set option SO_REUSEADDR, errno - ") +
        strerror(errno));
    return false;
  }
  return true;
}

bool start_listen(int file_descr, int listen_backlog,
                  std::string &detailed_error) {
  if (0 != ::listen(file_descr, listen_backlog)) {
    detailed_error.append(std::string("server listen is failed, errno - ") +
                          strerror(errno));
    return false;
  }
  return true;
}

accept_connection_result
accept_new_connection(proto::ip::address::version ip_version, int server_fd) {
  accept_connection_result res;
  switch (ip_version) {
  case proto::ip::address::version::e_v4: {
    struct sockaddr_in t_peer_addr = {0, 0, {0}, {0}};
    socklen_t addrlen = sizeof(t_peer_addr);
    int new_fd = -1;
    while (true) {
      new_fd = accept(server_fd, (struct sockaddr *)(&t_peer_addr), &addrlen);
      if (-1 == new_fd) {
        if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno)
          break;
      } else
        break;
    }

    if (-1 != new_fd) {
      res._client_fd = new_fd;
      res._peer_addr = proto::ip::full_address(t_peer_addr);
    }
    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 t_peer_addr = {0, 0, 0, {{{0}}}, 0};
    socklen_t addrlen = sizeof(t_peer_addr);
    int new_fd = -1;
    while (true) {
      new_fd = accept(server_fd, (struct sockaddr *)(&t_peer_addr), &addrlen);
      if (-1 == new_fd) {
        if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno)
          break;
      } else
        break;
    }
    if (-1 != new_fd) {
      res._client_fd = new_fd;
      res._peer_addr = proto::ip::full_address(t_peer_addr);
    }
    break;
  }
  default:
    break;
  }
  if (res._client_fd) {
    res._self_address = get_local_address(ip_version, *res._client_fd);
  }
  return res;
}

} // namespace bro::net
