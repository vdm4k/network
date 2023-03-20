#include <netinet/tcp.h>
#include <network/libev/libev.h>
#include <network/tcp/stream.h>
#include <sys/ioctl.h>

namespace bro::net::tcp {

void stream::set_socket_specific_options(
    proto::ip::address::version /*addr_ver*/) {
#ifdef TCP_NODELAY
  /* Set the NODELAY option */
  int optval = 1;
  if (-1 == ::setsockopt(_file_descr, IPPROTO_TCP, TCP_NODELAY,
                         reinterpret_cast<char const *>(&optval),
                         sizeof(optval))) {
  }
#endif  // TCP_NODELAY
}

}  // namespace bro::net::tcp
