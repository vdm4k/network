#include <network/sctp/ssl/listen/stream.h>
#include <network/sctp/ssl/send/stream.h>
#include <network/tcp/ssl/common.h>

//#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
//#include <openssl/pem.h>
//#include <openssl/x509.h>
//#include <openssl/x509_vfy.h>

typedef uint64_t ctx_option_t;

namespace bro::net::sctp::ssl::listen {

stream::~stream() {
  cleanup();
}

std::unique_ptr<strm::stream> stream::generate_send_stream() {
  return std::make_unique<bro::net::sctp::ssl::send::stream>();
}

bool stream::fill_send_stream(accept_connection_res const &result, std::unique_ptr<strm::stream> &sck) {
  if (!sctp::listen::stream::fill_send_stream(result, sck))
    return false;

  ssl::send::stream *s = (ssl::send::stream *) sck.get();
  s->_ctx = SSL_new(_server_ctx);
  if (!s->_ctx) {
    s->set_detailed_error("couldn't create new ssl context " + tcp::ssl::ssl_error());
    s->set_connection_state(state::e_failed);
    s->cleanup();
    return false;
  }
  auto *bio = BIO_new_dgram_sctp(s->get_fd(), BIO_NOCLOSE);
  if (!bio) {
    s->set_detailed_error("couldn't create new bio " + tcp::ssl::ssl_error());
    s->set_connection_state(state::e_failed);
    s->cleanup();
    return false;
  }

  SSL_set_bio(s->_ctx, bio, bio);

  int res = SSL_accept(s->_ctx);
  if (res <= 0) {
    res = SSL_get_error(s->_ctx, res);
    if (res != SSL_ERROR_WANT_READ) {
      s->set_detailed_error("SSL_accept failed with " + tcp::ssl::ssl_error());
      s->set_connection_state(state::e_failed);
      s->cleanup();
      return false;
    }
  }

  return true;
}

bool stream::init(settings *listen_params) {
  if (!tcp::ssl::init_openSSL()) {
    set_detailed_error("coulnd't init ssl library " + tcp::ssl::ssl_error());
    set_connection_state(state::e_failed);
    cleanup();
    return false;
  }

  if (!sctp::listen::stream::init(listen_params))
    return false;
  _settings = *listen_params;

  _server_ctx = SSL_CTX_new(DTLS_server_method());

  if (!_server_ctx) {
    set_detailed_error("couldn't create ssl server context " + tcp::ssl::ssl_error());
    set_connection_state(state::e_failed);
    cleanup();
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
      cleanup();
      return false;
    }
  }

  _fake_ctx = SSL_new(_server_ctx);
  if (!_fake_ctx) {
    set_detailed_error("couldn't create ssl ctx: " + tcp::ssl::ssl_error());
    set_connection_state(state::e_failed);
    cleanup();
    return false;
  }

  /* Create DTLS/SCTP BIO and connect */
  auto *bio = BIO_new_dgram_sctp(get_fd(), BIO_CLOSE);

  if (!bio) {
    set_detailed_error("couldn't create bio: " + tcp::ssl::ssl_error());
    set_connection_state(state::e_failed);
    cleanup();
    return false;
  }

  SSL_set_bio(_fake_ctx, bio, bio);

  //NOTE: Client has to authenticate
  if (_settings._need_auth) {
    SSL_CTX_set_verify(_server_ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, nullptr); // need add verify_callback
  } else {
    SSL_CTX_set_verify(_server_ctx, SSL_VERIFY_NONE, nullptr);
  }

  return true;
}

void stream::cleanup() {
  if (_fake_ctx) {
    SSL_shutdown(_fake_ctx);
    SSL_free(_fake_ctx);
    _fake_ctx = nullptr;
  }

  if (_server_ctx) {
    SSL_CTX_free(_server_ctx);
    _server_ctx = nullptr;
  }
  sctp::listen::stream::cleanup();
}

} // namespace bro::net::sctp::ssl::listen
