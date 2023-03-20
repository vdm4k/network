#include <netinet/tcp.h>
#include <network/libev/libev.h>
#include <network/tcp/settings.h>
#include <network/tcp/stream.h>
#include <sys/ioctl.h>

namespace bro::net::tcp {

void stream::set_socket_specific_options() {
  {
    int mode = 1;
    ioctl(_file_descr, FIONBIO, &mode);
    settings *sparam = (settings *)get_settings();
    if (sparam->_buffer_size) {
      int optval = *sparam->_buffer_size;
#ifdef SO_SNDBUF
      if (-1 == setsockopt(_file_descr, SOL_SOCKET, SO_SNDBUF,
                           reinterpret_cast<char const *>(&optval),
                           sizeof(optval))) {
      }
#endif  // SO_SNDBUF
#ifdef SO_RCVBUF
      if (-1 == setsockopt(_file_descr, SOL_SOCKET, SO_RCVBUF,
                           reinterpret_cast<char const *>(&optval),
                           sizeof(optval))) {
      }
#endif  // SO_RCVBUF
    }
  }
  {
#ifdef TCP_NODELAY
    /* Set the NODELAY option */
    int optval = 1;
    if (-1 == ::setsockopt(_file_descr, IPPROTO_TCP, TCP_NODELAY,
                           reinterpret_cast<char const *>(&optval),
                           sizeof(optval))) {
    }
#endif  // TCP_NODELAY
  }
}

bool stream::create_socket(proto::ip::address::version version) {
  int af_type =
      proto::ip::address::version::e_v6 == version ? AF_INET6 : AF_INET;
  int rc = ::socket(af_type, SOCK_STREAM, IPPROTO_TCP);
  if (-1 != rc) {
    _file_descr = rc;
    set_socket_specific_options();
  }
  return rc != -1;
}

}  // namespace bro::net::tcp
