#include <network/common.h>
#include <network/stream.h>
#include <string.h>

#ifdef WITH_SCTP
#include <netinet/sctp.h>
#endif
namespace bro::net {

std::optional<proto::ip::full_address> get_address_from_fd(proto::ip::address::version ver, int fd) {
  switch (ver) {
  case proto::ip::address::version::e_v4: {
    struct sockaddr_in t_local_addr = {0, 0, {0}, {0}};
    socklen_t addrlen = sizeof(t_local_addr);
    if (0 == getsockname(fd, (struct sockaddr *) &t_local_addr, &addrlen))
      return proto::ip::full_address(t_local_addr);
    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 t_local_addr = {0, 0, 0, {{{0}}}, 0};
    socklen_t addrlen = sizeof(t_local_addr);
    if (0 == getsockname(fd, (struct sockaddr *) &t_local_addr, &addrlen))
      return proto::ip::full_address(t_local_addr);
    break;
  }
  case proto::ip::address::version::e_none:
    break;
  }
  return std::nullopt;
}

proto::ip::full_address get_address_from_fd(proto::ip::address::version ver, int fd, std::string &detailed_error) {
  switch (ver) {
  case proto::ip::address::version::e_v4: {
    struct sockaddr_in t_local_addr = {0, 0, {0}, {0}};
    socklen_t addrlen = sizeof(t_local_addr);
    if (0 == getsockname(fd, (struct sockaddr *) &t_local_addr, &addrlen))
      return proto::ip::full_address(t_local_addr);
    detailed_error.append(std::string("couldn't get address, errno - ") + strerror(errno));
    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 t_local_addr = {0, 0, 0, {{{0}}}, 0};
    socklen_t addrlen = sizeof(t_local_addr);
    if (0 == getsockname(fd, (struct sockaddr *) &t_local_addr, &addrlen))
      return proto::ip::full_address(t_local_addr);
    detailed_error.append(std::string("couldn't get address, errno - ") + strerror(errno));
    break;
  }
  case proto::ip::address::version::e_none: {
    detailed_error = "incorrect address type";
    break;
  }
  }
  return {};
}

bool bind_on_address(proto::ip::full_address &self_address, int file_descr, std::string &detailed_error) {
  switch (self_address.get_address().get_version()) {
  case proto::ip::address::version::e_v4: {
    sockaddr_in local_addr = self_address.to_native_v4();
    if (0 == ::bind(file_descr, reinterpret_cast<sockaddr *>(&local_addr), sizeof(local_addr)))
      return true;
    detailed_error.append("couldn't bind on address - " + self_address.to_string() + ", errno - " + strerror(errno));
    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 local_addr = self_address.to_native_v6();
    if (0 == ::bind(file_descr, reinterpret_cast<sockaddr *>(&local_addr), sizeof(local_addr)))
      return true;
    detailed_error.append("couldn't bind on address - " + self_address.to_string() + ", errno - " + strerror(errno));
    break;
  }
  default:
    detailed_error.append("incorrect self address pass to function bind_on_address");
    break;
  }
  return false;
}

#ifdef WITH_SCTP
bool bind_on_sctp_address(proto::ip::full_address &self_address, int file_descr, std::string &detailed_error) {
  switch (self_address.get_address().get_version()) {
  case proto::ip::address::version::e_v4: {
    sockaddr_in local_addr = self_address.to_native_v4();
    if (0 == sctp_bindx(file_descr, reinterpret_cast<sockaddr *>(&local_addr), 1, SCTP_BINDX_ADD_ADDR))
      return true;
    detailed_error.append("couldn't bind sctp on address - " + self_address.to_string() + ", errno - "
                          + strerror(errno));
    break;
  }
  case proto::ip::address::version::e_v6: {
    sockaddr_in6 local_addr = self_address.to_native_v6();
    if (0 == sctp_bindx(file_descr, reinterpret_cast<sockaddr *>(&local_addr), 1, SCTP_BINDX_ADD_ADDR))
      return true;
    detailed_error.append("couldn't bind sctp on address - " + self_address.to_string() + ", errno - "
                          + strerror(errno));
    break;
  }
  default:
    detailed_error.append("incorrect self address pass to function bind_on_address");
    break;
  }
  return false;
}

bool asconf_on(int file_descr, std::string &detailed_error) {
#ifdef SCTP_AUTO_ASCONF
//  int optval = 1;
//  if (setsockopt(file_descr, IPPROTO_SCTP, SCTP_AUTO_ASCONF, &optval, sizeof(optval)) < 0) {
//    detailed_error.append(std::string("couldn't set option asconf for sctp, errno - ") + strerror(errno));
//    return false;
//  }
#endif /* SCTP_AUTO_ASCONF */
  return true;
}

bool connect_sctp_streams(proto::ip::full_address const &peer_addr, int file_descr, std::string &detailed_error) {
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
    detailed_error.append("incorrect peer address");
    return false;
  }
  }
  if (0 == rc || EINPROGRESS == errno)
    return true;
  detailed_error.append("coulnd't connect to server - " + peer_addr.to_string() + ", errno - " + strerror(errno));
  return false;
}

#endif

bool connect_stream(const proto::ip::full_address &peer_addr, int file_descr, std::string &detailed_error) {
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
    detailed_error.append("incorrect peer address");
    return false;
  }
  }
  if (0 == rc || EINPROGRESS == errno)
    return true;
  detailed_error.append("coulnd't connect to server - " + peer_addr.to_string() + ", errno - " + strerror(errno));
  return false;
}

bool reuse_address(int file_descr, std::string &detailed_error) {
  int reuseaddr = 1;
  if (-1 == setsockopt(file_descr, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const void *>(&reuseaddr), sizeof(int))) {
    detailed_error.append(std::string("couldn't set option SO_REUSEADDR, errno - ") + strerror(errno));
    return false;
  }
  return true;
}

bool start_listen(int file_descr, int listen_backlog, std::string &detailed_error) {
  if (0 != ::listen(file_descr, listen_backlog)) {
    detailed_error.append(std::string("server listen is failed, errno - ") + strerror(errno));
    return false;
  }
  return true;
}

accept_connection_res accept_connection(proto::ip::address::version ip_version, int server_fd) {
  new_connection_details res;
  res._client_fd = -1;
  switch (ip_version) {
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
    if (auto addr = get_address_from_fd(ip_version, res._client_fd); addr) // NOTE: actualy it never fails
      res._self_address = *addr;
    return res;
  }
  return std::nullopt;
}

} // namespace bro::net
