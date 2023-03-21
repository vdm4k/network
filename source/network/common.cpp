#include <arpa/inet.h>
#include <ifaddrs.h>
#include <network/common.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

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

bool fill_sockaddr(proto::ip::full_address &ipaddr, sockaddr_in &addr,
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
      detailed_error.append("incorrect address type\n");
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
                            strerror(errno) + "\n");

      break;
    }
    case proto::ip::address::version::e_v6: {
      sockaddr_in6 local_addr = self_address.to_native_v6();
      if (0 == ::bind(file_descr, reinterpret_cast<sockaddr *>(&local_addr),
                      sizeof(local_addr)))
        return true;
      detailed_error.append("couldn't bind on address - " +
                            self_address.to_string() + ", errno - " +
                            strerror(errno) + "\n");

      break;
    }
    default:
      detailed_error.append(
          "incorrect self address pass to function bind_on_address\n");
      break;
  }
  return false;
}

accept_connection_result accept_new_connection(
    proto::ip::address::version ip_version, int server_fd) {
  accept_connection_result res;
  switch (ip_version) {
    case proto::ip::address::version::e_v4: {
      struct sockaddr_in t_peer_addr = {0, 0, {0}, {0}};
      socklen_t addrlen = sizeof(t_peer_addr);
      int new_fd = -1;
      while (true) {
        new_fd = accept(server_fd, (struct sockaddr *)(&t_peer_addr), &addrlen);
        if (-1 == new_fd) {
          if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) break;
        } else
          break;
      }

      if (-1 != new_fd) {
        res._fd = new_fd;
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
          if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) break;
        } else
          break;
      }
      if (-1 != new_fd) {
        res._fd = new_fd;
        res._peer_addr = proto::ip::full_address(t_peer_addr);
      }
      break;
    }
    default:
      break;
  }
  if (res._fd) {
    res._self_address = get_local_address(ip_version, *res._fd);
  }
  return res;
}

}  // namespace bro::net
