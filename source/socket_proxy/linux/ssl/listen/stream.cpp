#include <socket_proxy/libev/libev.h>
#include <socket_proxy/linux/ssl/listen/stream.h>
#include <socket_proxy/linux/tcp/send/stream.h>

//#include <openssl/bio.h>
#include <openssl/ssl.h>
//#include <openssl/err.h>
//#include <openssl/pem.h>
//#include <openssl/x509.h>
//#include <openssl/x509_vfy.h>

namespace jkl::sp::tcp::ssl::listen {

void init_SSL() {
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
    (defined(LIBRESSL_VERSION_NUMBER) &&      \
     LIBRESSL_VERSION_NUMBER < 0x20700000L)
  static std::once_flag flag;
  std::call_once(flag, []() {
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
    SSL_load_error_strings(); /* readable error messages */
    SSL_library_init();       /* initialize library */
  });
#endif  // ENABLE_SSL
  // ssl sctp использует для отправки сообщений sendmsg без флагов
  // => у нас могут появлятся SIGPIPE
  signal(SIGPIPE, SIG_IGN);
}

void incoming_connection_cb(struct ev_loop * /*loop*/, ev_io *w,
                            int /*revents*/) {
  int new_fd = -1;
  auto *conn = reinterpret_cast<stream *>(w->data);

  jkl::proto::ip::full_address peer_addr;
  switch (conn->get_self_address().get_address().get_version()) {
    case jkl::proto::ip::address::version::e_v4: {
      struct sockaddr_in t_peer_addr = {0, 0, {0}, {0}};
      socklen_t addrlen = sizeof(t_peer_addr);
      while (true) {
        new_fd = accept(
            w->fd, reinterpret_cast<struct sockaddr *>(&t_peer_addr), &addrlen);
        if (-1 == new_fd) {
          if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) break;
        } else
          break;
      }

      if (-1 != new_fd) {
        peer_addr = jkl::proto::ip::full_address(
            jkl::proto::ip::v4::address(t_peer_addr.sin_addr.s_addr),
            htons(t_peer_addr.sin_port));
      }
      break;
    }
    case jkl::proto::ip::address::version::e_v6: {
      sockaddr_in6 t_peer_addr = {0, 0, 0, {{{0}}}, 0};
      socklen_t addrlen = sizeof(t_peer_addr);
      while (true) {
        new_fd = accept(
            w->fd, reinterpret_cast<struct sockaddr *>(&t_peer_addr), &addrlen);
        if (-1 == new_fd) {
          if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) break;
        } else
          break;
      }
      if (-1 != new_fd) {
        char addr_buf[50];
        inet_ntop(AF_INET6, &t_peer_addr.sin6_addr, addr_buf, sizeof(addr_buf));
        peer_addr =
            jkl::proto::ip::full_address(jkl::proto::ip::v6::address(addr_buf),
                                         htons(t_peer_addr.sin6_port));
      }
      break;
    }
    default:
      break;
  }

  jkl::proto::ip::full_address self_address;
  if (-1 != new_fd) {
    stream::get_local_address(peer_addr.get_address().get_version(), new_fd,
                              self_address);
  }
  conn->handle_incoming_connection(new_fd, peer_addr, self_address);
}

stream::~stream() { stop_events(); }

void stream::reset_statistic() {
  _statistic._success_accept_connections = 0;
  _statistic._failed_to_accept_connections = 0;
}

bool stream::create_listen_socket() {
  if (!create_socket()) return false;

  int reuseaddr = 1;
  if (-1 == setsockopt(_file_descr, SOL_SOCKET, SO_REUSEADDR,
                       reinterpret_cast<const void *>(&reuseaddr),
                       sizeof(int))) {
    set_detailed_error("couldn't set option SO_REUSEADDR");
    ::close(_file_descr);
    _file_descr = -1;
    return false;
  }

  return bind_on_address(_settings._listen_address);
}

void stream::handle_incoming_connection(
    int file_descr, jkl::proto::ip::full_address const &peer_addr,
    proto::ip::full_address const &self_addr) {
  auto sck = std::make_unique<send::stream>();

  if (_settings._proc_in_conn)
    _settings._proc_in_conn(std::move(sck), _settings._in_conn_handler_data);
}

void stream::assign_loop(struct ev_loop *loop) {
  _loop = loop;
  ev::init(_connect_io, incoming_connection_cb, _file_descr, EV_READ, this);
  ev::start(_connect_io, _loop);
}

jkl::proto::ip::full_address const &stream::get_self_address() const {
  return _settings._listen_address;
}

bool stream::init(settings *listen_params) {
  bool res{false};
  _settings = *listen_params;

#if OPENSSL_VERSION_NUMBER >= 0x10100000
  _ctx = SSL_CTX_new(TLS_method());
#else
  ssl_context = SSL_CTX_new(TLSv1_2_method());
#endif

  unsigned long ssl_opts = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);

  if (!_settings._enable_sslv2) {
    ssl_opts =
        (SSL_OP_NO_SSLv2 |
         SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);  // Disabling SSLv2
                                                          // will leave v3 and
                                                          // TSLv1 for
                                                          // negotiation
  }

  return res;
}

void stream::stop_events() { ev::stop(_connect_io, _loop); }

}  // namespace jkl::sp::tcp::ssl::listen
