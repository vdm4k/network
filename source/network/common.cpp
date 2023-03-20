#include <arpa/inet.h>
#include <ifaddrs.h>
#include <network/common.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace bro::net {
uint32_t find_scope_id(const proto::ip::v6::address &addr) {
  uint32_t scope_id{0};
  struct ifaddrs *ifap{nullptr}, *ifa{nullptr};
  getifaddrs(&ifap);

  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
    if (ifa && ifa->ifa_addr && AF_INET6 == ifa->ifa_addr->sa_family) {
      struct sockaddr_in6 *in6 =
          reinterpret_cast<struct sockaddr_in6 *>(ifa->ifa_addr);
      char addr_buf[50];
      inet_ntop(AF_INET6, &in6->sin6_addr, addr_buf, sizeof(addr_buf));
      proto::ip::v6::address addr_s(addr_buf);
      if (addr == addr_s) {
        scope_id = in6->sin6_scope_id;
        break;
      }
    }
  }

  freeifaddrs(ifap);
  return scope_id;
}

bool get_local_address(proto::ip::address::version ver, int fd,
                       proto::ip::full_address &addr) {
  if (fd > 0) {
    switch (ver) {
      case proto::ip::address::version::e_v4: {
        struct sockaddr_in t_local_addr = {0, 0, {0}, {0}};
        socklen_t addrlen = sizeof(t_local_addr);
        getsockname(fd, (struct sockaddr *)&t_local_addr, &addrlen);
        addr = proto::ip::full_address(
            proto::ip::address(
                proto::ip::v4::address(t_local_addr.sin_addr.s_addr)),
            htons(t_local_addr.sin_port));
        return true;
      }
      case proto::ip::address::version::e_v6: {
        sockaddr_in6 t_local_addr = {0, 0, 0, {{{0}}}, 0};
        socklen_t addrlen = sizeof(t_local_addr);
        char addr_buf[50];
        getsockname(fd, (struct sockaddr *)&t_local_addr, &addrlen);
        inet_ntop(AF_INET6, &t_local_addr.sin6_addr, addr_buf,
                  sizeof(addr_buf));
        addr = proto::ip::full_address(
            proto::ip::address(proto::ip::v6::address(addr_buf)),
            htons(t_local_addr.sin6_port));
        return true;
      }
      default:
        break;
    }
  }
  return false;
}

bool fill_sockaddr(const proto::ip::full_address &ipaddr, sockaddr_in &addr,
                   std::string &detailed_error) {
  switch (ipaddr.get_address().get_version()) {
    case proto::ip::address::version::e_v4: {
      addr = {0, 0, {0}, {0}};
      addr.sin_family = AF_INET;
      memcpy(&addr.sin_addr.s_addr, ipaddr.get_address().get_data(),
             proto::ip::v4::address::e_bytes_size);
      addr.sin_port = __builtin_bswap16(ipaddr.get_port());
      return true;
    }
    case proto::ip::address::version::e_v6: {
      uint32_t lscope_id{find_scope_id(ipaddr.get_address().to_v6())};
      if (lscope_id) {
        sockaddr_in6 local_addr = {0, 0, 0, {{{0}}}, 0};
        memset(&local_addr, 0, sizeof(sockaddr_in6));
        local_addr.sin6_family = AF_INET6;
        memcpy(&local_addr.sin6_addr, ipaddr.get_address().get_data(),
               proto::ip::v6::address::e_bytes_size);
        local_addr.sin6_port = __builtin_bswap16(ipaddr.get_port());
        local_addr.sin6_scope_id = lscope_id;
        auto *p_addr = reinterpret_cast<sockaddr_in6 *>(&addr);
        *p_addr = local_addr;
        return true;
      } else {
        detailed_error.append("couldn't find scope_id for address - " +
                              ipaddr.to_string());
      }
      break;
    }
    default: {
      detailed_error.append("incorrect address type\n");
      break;
    }
  }
  return false;
}

bool bind_on_address(proto::ip::full_address const &self_address,
                     int file_descr, std::string &detailed_error) {
  switch (self_address.get_address().get_version()) {
    case proto::ip::address::version::e_v4: {
      sockaddr_in local_addr = {0, 0, {0}, {0}};
      if (0 < fill_sockaddr(self_address, local_addr, detailed_error)) {
        if (0 == ::bind(file_descr, reinterpret_cast<sockaddr *>(&local_addr),
                        sizeof(local_addr)))
          return true;
        detailed_error.append("couldn't bind on address - " +
                              self_address.to_string() + ", errno - " +
                              strerror(errno) + "\n");
      }
      break;
    }
    case proto::ip::address::version::e_v6: {
      sockaddr_in6 local_addr = {0, 0, 0, {{{0}}}, 0};
      if (fill_sockaddr(self_address, (sockaddr_in &)(local_addr),
                        detailed_error) > 0) {
        if (0 == ::bind(file_descr, reinterpret_cast<sockaddr *>(&local_addr),
                        sizeof(local_addr)))
          return true;
        detailed_error.append("couldn't bind on address - " +
                              self_address.to_string() + ", errno - " +
                              strerror(errno) + "\n");
      }
      break;
    }
    default:
      detailed_error.append(
          "incorrect self address pass to function bind_on_address\n");
      break;
  }
  return false;
}

}  // namespace bro::net
