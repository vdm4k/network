#include <netinet/tcp.h>
#include <network/libev/libev.h>
#include <network/tcp/stream.h>
#include <sys/ioctl.h>

namespace bro::net::tcp {

bool stream::set_socket_specific_options(proto::ip::address::version /*addr_ver*/) {
#if defined __linux__ && defined TCP_NODELAY
  /* Set the NODELAY option */
  int optval = 1;
  if (-1
      == ::setsockopt(_file_descr, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char const *>(&optval), sizeof(optval))) {
    set_detailed_error("coulnd't set tcp nodelay option");
    set_connection_state(state::e_failed);
    return false;
  }
#endif // TCP_NODELAY
  return true;
}

} // namespace bro::net::tcp
