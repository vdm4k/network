#include <atomic>
#include <network/udp/ssl/listen/stream.h>
#include <network/udp/ssl/send/stream.h>
#include <network/tcp/ssl/common.h>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>

typedef uint64_t ctx_option_t;

namespace bro::net::udp::ssl::listen {

int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
  unsigned char *buffer, result[EVP_MAX_MD_SIZE];
  unsigned int length = 0, resultlength;
  union {
    struct sockaddr_storage ss;
    struct sockaddr_in6 s6;
    struct sockaddr_in s4;
  } peer;

  /* Read peer information */
  (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

  /* Create buffer with peer's address and port */
  length = 0;
  switch (peer.ss.ss_family) {
  case AF_INET:
    length += sizeof(struct in_addr);
    break;
  case AF_INET6:
    length += sizeof(struct in6_addr);
    break;
  default:
    return 0;
    break;
  }
  length += sizeof(in_port_t);
  buffer = (unsigned char *) OPENSSL_malloc(length);

  if (buffer == NULL) {
    return 0;
  }

  switch (peer.ss.ss_family) {
  case AF_INET:
    memcpy(buffer, &peer.s4.sin_port, sizeof(in_port_t));
    memcpy(buffer + sizeof(peer.s4.sin_port), &peer.s4.sin_addr, sizeof(struct in_addr));
    break;
  case AF_INET6:
    memcpy(buffer, &peer.s6.sin6_port, sizeof(in_port_t));
    memcpy(buffer + sizeof(in_port_t), &peer.s6.sin6_addr, sizeof(struct in6_addr));
    break;
  default:
    return 0;
    break;
  }

  auto [salt, salt_size] = tcp::ssl::get_salt();

  /* Calculate HMAC of buffer using the secret */
  HMAC(EVP_sha1(), (void const *) salt, salt_size, (unsigned char const *) buffer, length, result, &resultlength);
  OPENSSL_free(buffer);
  memcpy(cookie, result, resultlength);
  *cookie_len = resultlength;
  return 1;
}

int verify_cookie(SSL *ssl, unsigned char const *cookie, unsigned int cookie_len) {
  unsigned char *buffer, result[EVP_MAX_MD_SIZE];
  unsigned int length = 0, resultlength;
  union {
    struct sockaddr_storage ss;
    struct sockaddr_in6 s6;
    struct sockaddr_in s4;
  } peer;

  /* Read peer information */
  (void) BIO_dgram_get_peer(SSL_get_rbio(ssl), &peer);

  /* Create buffer with peer's address and port */
  length = 0;
  switch (peer.ss.ss_family) {
  case AF_INET:
    length += sizeof(struct in_addr);
    break;
  case AF_INET6:
    length += sizeof(struct in6_addr);
    break;
  default:
    OPENSSL_assert(0);
    break;
  }
  length += sizeof(in_port_t);
  buffer = (unsigned char *) OPENSSL_malloc(length);

  if (buffer == NULL) {
    printf("out of memory\n");
    return 0;
  }

  switch (peer.ss.ss_family) {
  case AF_INET:
    memcpy(buffer, &peer.s4.sin_port, sizeof(in_port_t));
    memcpy(buffer + sizeof(in_port_t), &peer.s4.sin_addr, sizeof(struct in_addr));
    break;
  case AF_INET6:
    memcpy(buffer, &peer.s6.sin6_port, sizeof(in_port_t));
    memcpy(buffer + sizeof(in_port_t), &peer.s6.sin6_addr, sizeof(struct in6_addr));
    break;
  default:
    OPENSSL_assert(0);
    break;
  }

  /* Calculate HMAC of buffer using the secret */
  auto [salt, salt_size] = tcp::ssl::get_salt();
  HMAC(EVP_sha1(), (void const *) salt, salt_size, (unsigned char const *) buffer, length, result, &resultlength);
  OPENSSL_free(buffer);
  if (cookie_len == resultlength && memcmp(result, cookie, resultlength) == 0)
    return 1;

  return 0;
}

int dtls_verify_callback(int /*ok*/, X509_STORE_CTX * /*ctx*/) {
  /* This function should ask the user
     * if he trusts the received certificate.
     * Here we always trust.
     */
  return 1;
}

stream::~stream() {
  stream::cleanup();
}

std::unique_ptr<net::stream> stream::generate_send_stream() {
  return std::make_unique<bro::net::udp::ssl::send::stream>();
}

bool stream::fill_send_stream(accept_connection_res const &result, std::unique_ptr<net::stream> &sck) {
  if (!net::listen::stream::fill_send_stream(result, sck))
    return false;

  ssl::send::stream *s = (ssl::send::stream *) sck.get();
  s->_ctx = SSL_new(_server_ctx);
  if (!s->_ctx) {
    s->set_detailed_error(tcp::ssl::fill_error("couldn't create ssl context"));
    return false;
  }
  auto *bio = BIO_new_dgram(s->get_fd(), BIO_NOCLOSE);
  if (!bio) {
    s->set_detailed_error(tcp::ssl::fill_error("couldn't create bio"));
    return false;
  }

  SSL_set_bio(s->_ctx, bio, bio);

  int err_c = SSL_accept(s->_ctx);
  if (err_c <= 0) {
    err_c = SSL_get_error(s->_ctx, err_c);
    if (err_c != SSL_ERROR_WANT_READ) {
      s->set_detailed_error(tcp::ssl::fill_error("SSL_accept failed", err_c));
      return false;
    }
  }

  return true;
}

bool stream::create_listen_socket() {
  if (create_socket(_settings._listen_address.get_address().get_version(), socket_type::e_udp)
      && reuse_address(get_fd(), get_error_description())
      && bind_on_address(_settings._listen_address, get_fd(), get_error_description()))
    return true;
  set_connection_state(state::e_failed);
  return false;
}

/**
 * \brief universal address for openSSL
 */
union ssl_addrs {
  struct sockaddr_storage ss; ///< using for get address family
  struct sockaddr_in s4;      ///< ipv4
  struct sockaddr_in6 s6;     ///< ipv6
};

void stream::handle_incoming_connection() {
  ssl_addrs client_addr;
  if (DTLSv1_listen(_dtls_ctx, (BIO_ADDR *) &client_addr) > 0) {
    if (!_settings._proc_in_conn)
      return;

    auto sck = std::make_unique<bro::net::udp::ssl::send::stream>();
    sck->_settings._self_addr = _settings._listen_address;
    sck->_ctx = _dtls_ctx;

    auto init_stream = [&]() {
      proto::ip::full_address peer_addr;
      switch (client_addr.ss.ss_family) {
      case AF_INET:
        peer_addr = client_addr.s4;
        break;
      case AF_INET6:
        peer_addr = client_addr.s6;
        break;
      default:
        sck->set_detailed_error("unsupported af family from openssl DTLSv1_listen");
        return false;
      }
      sck->_settings._peer_addr = peer_addr;

      if (sck->create_socket(_settings._listen_address.get_address().get_version(), socket_type::e_udp)
          && reuse_address(sck->get_fd(), sck->get_error_description())
          && bind_on_address(_settings._listen_address, sck->get_fd(), sck->get_error_description())
          && connect_stream(peer_addr, sck->get_fd(), sck->get_error_description())) {
        /* Set new fd and set BIO to connected */
        BIO_set_fd(SSL_get_rbio(sck->_ctx), sck->get_fd(), BIO_NOCLOSE);
        if (int err_c = BIO_ctrl(SSL_get_rbio(sck->_ctx), BIO_CTRL_DGRAM_SET_CONNECTED, 0, &client_addr.ss);
            0 >= err_c) {
          sck->set_detailed_error(
            tcp::ssl::fill_error("bio ctrl call failed with error for BIO_CTRL_DGRAM_SET_CONNECTED", err_c));
          return false;
        }

        int err_c = 0;
        for (err_c = SSL_accept(sck->_ctx); err_c == 0; err_c = SSL_accept(sck->_ctx))
          ;
        if (err_c < 0) {
          err_c = SSL_get_error(sck->_ctx, err_c);
          if (err_c != SSL_ERROR_WANT_READ) {
            sck->set_detailed_error(tcp::ssl::fill_error("SSL_accept failed", err_c));
            return false;
          }
        }

        sck->set_connection_state(state::e_established);
        return true;
      }
      sck->set_connection_state(state::e_failed);
      return false;
    };

    if (init_stream())
      _statistic._success_accept_connections++;
    else
      _statistic._failed_to_accept_connections++;
    _settings._proc_in_conn(std::move(sck), _settings._in_conn_handler_data);
    generate_new_dtls_context();
  }
}

bool stream::generate_new_dtls_context() {
  _dtls_ctx = SSL_new(_server_ctx);
  if (!_dtls_ctx) {
    set_detailed_error(tcp::ssl::fill_error("couldn't create ssl ctx"));
    return false;
  }

  /* Create DTLS/SCTP BIO. Init support dtls in ssl*/
  auto *bio = BIO_new_dgram(get_fd(), BIO_NOCLOSE);
  if (!bio) {
    set_detailed_error(tcp::ssl::fill_error("couldn't create bio"));
    return false;
  }

  SSL_set_bio(_dtls_ctx, bio, bio);
  SSL_set_options(_dtls_ctx, SSL_OP_COOKIE_EXCHANGE);
  return true;
}

bool stream::init(settings *listen_params) {
  if (!tcp::ssl::init_openSSL()) {
    set_detailed_error(tcp::ssl::fill_error("coulnd't init ssl library"));
    return false;
  }
  _settings = *listen_params;

  if (create_listen_socket()) {
    set_connection_state(state::e_wait);
  } else {
    return false;
  }

  _server_ctx = SSL_CTX_new(DTLS_server_method());

  if (!_server_ctx) {
    set_detailed_error(tcp::ssl::fill_error("couldn't create ssl server context"));
  }

  ctx_option_t ctx_options = (SSL_OP_ALL & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS);

#ifdef SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
  /* mitigate CVE-2010-4180 */
  ctx_options &= ~SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
  /* unless the user explicitly asks to allow the protocol vulnerability we
       use the work-around */
  if (!_settings._enable_empty_fragments)
    ctx_options &= ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
#endif

  if (!_settings._enable_sslv2) {
    ctx_options |= SSL_OP_NO_SSLv2;
  }

  SSL_CTX_set_options(_server_ctx, ctx_options);

  //NOTE:
  //  probably we can check return mask,
  //    but I don't see why we need it and how to handle it SSL_CTX_set_options(_server_ctx, ctx_options);

  if (!_settings._certificate_path.empty() && !_settings._key_path.empty()) {
    if (!tcp::ssl::set_check_ceritficate(_server_ctx,
                                         _settings._certificate_path,
                                         _settings._key_path,
                                         get_error_description())) {
      set_connection_state(state::e_failed);
      return false;
    }
  }

  SSL_CTX_set_cookie_generate_cb(_server_ctx, generate_cookie);
  SSL_CTX_set_cookie_verify_cb(_server_ctx, &verify_cookie);

  //NOTE: Client has to authenticate
  if (_settings._need_auth) {
    SSL_CTX_set_verify(_server_ctx,
                       SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                       dtls_verify_callback); // need add verify_callback
  } else {
    SSL_CTX_set_verify(_server_ctx, SSL_VERIFY_NONE, nullptr);
  }

  return generate_new_dtls_context();
}

void stream::cleanup() {
  if (_dtls_ctx) {
    SSL_shutdown(_dtls_ctx);
    SSL_free(_dtls_ctx);
    _dtls_ctx = nullptr;
  }

  if (_server_ctx) {
    SSL_CTX_free(_server_ctx);
    _server_ctx = nullptr;
  }
  net::listen::stream::cleanup();
}

} // namespace bro::net::udp::ssl::listen
