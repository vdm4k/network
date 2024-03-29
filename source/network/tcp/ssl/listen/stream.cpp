#include <network/common/ssl.h>
#include <network/tcp/ssl/listen/stream.h>
#include <network/tcp/ssl/send/stream.h>

//#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
//#include <openssl/pem.h>
//#include <openssl/x509.h>
//#include <openssl/x509_vfy.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
typedef uint64_t ctx_option_t;
#else
typedef long ctx_option_t;
#endif

namespace bro::net::tcp::ssl::listen {

stream::~stream() {
  stream::cleanup();
}

std::unique_ptr<net::stream> stream::generate_send_stream() {
  return std::make_unique<bro::net::tcp::ssl::send::stream>();
}

bool stream::fill_send_stream(accept_connection_res const &result, std::unique_ptr<net::stream> &sck) {
  if (!tcp::listen::stream::fill_send_stream(result, sck))
    return false;

  ssl::send::stream *s = (ssl::send::stream *) sck.get();
  s->_ctx = SSL_new(_ctx);
  if (!s->_ctx) {
    s->set_detailed_error(net::ssl::fill_error("couldn't create ssl context"));
    return false;
  }

  if (!SSL_set_fd(s->_ctx, s->get_fd())) {
    s->set_detailed_error(net::ssl::fill_error("couldn't set file descriptor to context"));
    return false;
  }
  int err_c = SSL_accept(s->_ctx);
  if (err_c <= 0) {
    err_c = SSL_get_error(s->_ctx, err_c);
    if (err_c != SSL_ERROR_WANT_READ) {
      s->set_detailed_error(net::ssl::fill_error("SSL_accept failed", err_c));
      return false;
    }
  }

  if (_settings._enable_http2) {
    unsigned char const *alpn = nullptr;
    unsigned int alpnlen = 0;
#ifndef OPENSSL_NO_NEXTPROTONEG
    SSL_get0_next_proto_negotiated(s->_ctx, &alpn, &alpnlen);
#endif /* !OPENSSL_NO_NEXTPROTONEG */
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    if (alpn == NULL) {
      SSL_get0_alpn_selected(s->_ctx, &alpn, &alpnlen);
    }
#endif /* OPENSSL_VERSION_NUMBER >= 0x10002000L */

    if (alpn == NULL || alpnlen != 2 || memcmp("h2", alpn, 2) != 0) {
      auto st = SSL_get_state(s->_ctx);
      if (TLS_ST_BEFORE != st) {
        s->set_detailed_error(net::ssl::fill_error("h2 isn't negotiated (need for http2)"));
        return false;
      }
    }
  }

  return true;
}

bool stream::init(settings *listen_params) {
  if (!net::ssl::init_openSSL()) {
    set_detailed_error(net::ssl::fill_error("coulnd't init ssl library"));
    return false;
  }
  if (!tcp::listen::stream::init(listen_params))
    return false;
  _settings = *listen_params;

  _ctx = SSL_CTX_new(TLS_server_method());
  if (!_ctx) {
    set_detailed_error(net::ssl::fill_error("couldn't create server context"));
    return false;
  }

  /*When we no longer need a read buffer or a write buffer for a given SSL, then
   * release the memory we were using to hold it. Using this flag can save
   * around 34k per idle SSL connection. This flag has no effect on SSL v2
   * connections, or on DTLS connections.*/
#ifdef SSL_MODE_RELEASE_BUFFERS
  SSL_CTX_set_mode(_ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

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

  if (_settings._enable_http2) {
// like in nghttp2
#ifdef SSL_OP_NO_TICKET
    ctx_options |= SSL_OP_NO_TICKET;
#endif

#ifdef SSL_OP_NO_COMPRESSION
    ctx_options |= SSL_OP_NO_COMPRESSION;
#endif

#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
    ctx_options |= SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
#endif
  }
  //NOTE: probably we can check return mask, but I don't see why we need it and how to handle it
  SSL_CTX_set_options(_ctx, ctx_options);

  if (!_settings._certificate_path.empty() && !_settings._key_path.empty()) {
    if (!net::ssl::set_check_ceritficate(_ctx,
                                         _settings._certificate_path,
                                         _settings._key_path,
                                         get_error_description())) {
      set_connection_state(state::e_failed);
      return false;
    }
  }
  return true;
}

void stream::cleanup() {
  if (_ctx) {
    SSL_CTX_free(_ctx);
    _ctx = nullptr;
  }
  tcp::listen::stream::cleanup();
}

} // namespace bro::net::tcp::ssl::listen
