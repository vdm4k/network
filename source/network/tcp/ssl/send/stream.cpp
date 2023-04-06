#include <network/tcp/ssl/common.h>
#include <network/tcp/ssl/send/stream.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace bro::net::tcp::ssl::send {

stream::~stream() {
  stream::cleanup();
}

void stream::cleanup() {
  if (_ctx) {
    SSL_shutdown(_ctx);
    SSL_free(_ctx);
    _ctx = nullptr;
  }

  if (_client_ctx) {
    SSL_CTX_free(_client_ctx);
    _client_ctx = nullptr;
  }
  tcp::send::stream::cleanup();
}

bool stream::init(settings *send_params) {
  if (!tcp::ssl::init_openSSL()) {
    set_detailed_error(tcp::ssl::fill_error("coulnd't init ssl library"));
    return false;
  }

  if (!bro::net::tcp::send::stream::init(send_params))
    return false;
  _settings = *send_params;
  ERR_clear_error();

  _client_ctx = SSL_CTX_new(TLS_client_method());
  if (!_client_ctx) {
    set_detailed_error(tcp::ssl::fill_error("coulnd't create ssl client context"));
    return false;
  }

  /*When we no longer need a read buffer or a write buffer for a given SSL, then
   * release the memory we were using to hold it. Using this flag can save
   * around 34k per idle SSL connection. This flag has no effect on SSL v2
   * connections, or on DTLS connections.*/
#ifdef SSL_MODE_RELEASE_BUFFERS
  SSL_CTX_set_mode(_client_ctx, SSL_MODE_RELEASE_BUFFERS);
#endif

  unsigned long ctx_options = SSL_OP_ALL;

#ifdef SSL_OP_NO_TICKET
  ctx_options |= SSL_OP_NO_TICKET;
#endif

#ifdef SSL_OP_NO_COMPRESSION
  ctx_options |= SSL_OP_NO_COMPRESSION;
#endif

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

#ifdef SSL_OP_SINGLE_ECDH_USE
    ctx_options |= SSL_OP_SINGLE_ECDH_USE;
#endif

#ifdef SSL_OP_NO_COMPRESSION
    ctx_options |= SSL_OP_NO_COMPRESSION;
#endif

#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
    ctx_options |= SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION;
#endif

    //    auto proto_list = get_default_alpn();
    //    SSL_CTX_set_alpn_protos(_client_ctx, proto_list.data(),
    //    proto_list.size());
  }
  //NOTE: probably we can check return mask, but I don't see why we need it and how to handle it
  SSL_CTX_set_options(_client_ctx, ctx_options);

  if (!_settings._certificate_path.empty() && !_settings._key_path.empty()) {
    if (!set_check_ceritficate(_client_ctx, _settings._certificate_path, _settings._key_path, get_error_description())) {
      set_connection_state(state::e_failed);
      return false;
    }
  }

  return true;
}

bool stream::connection_established() {
  if (!tcp::send::stream::connection_established()) {
    return false;
  }
  ERR_clear_error();

  _ctx = SSL_new(_client_ctx);
  if (!_ctx) {
    set_detailed_error(tcp::ssl::fill_error("couldn't create new ssl context"));
    return false;
  }

  if (!SSL_set_fd(_ctx, get_fd())) {
    set_detailed_error(tcp::ssl::fill_error("couldn't set file decriptor to bio"));
    return false;
  }
  int err_c = SSL_connect(_ctx);
  if (err_c <= 0) {
    err_c = SSL_get_error(_ctx, err_c);
    if (err_c != SSL_ERROR_WANT_READ) {
      set_detailed_error(tcp::ssl::fill_error("SSL_connect failed", err_c));
      return false;
    }
  }
  return true;
}

ssize_t stream::send_data(std::byte const *data, size_t data_size) {
  ssize_t sent = -1;
  while (SSL_get_shutdown(_ctx) != SSL_RECEIVED_SHUTDOWN) {
    ERR_clear_error();
    sent = SSL_write(_ctx, data, data_size);
    if (sent > 0) {
      ++_statistic._success_send_data;
      break;
    }

    int err_c = SSL_get_error(_ctx, sent);
    switch (err_c) {
    case SSL_ERROR_WANT_READ: {
      ++_statistic._retry_send_data;
      // waiting data from peer
      // hence just buffer out data
      disable_send_cb();
      return 0;
    }
    case SSL_ERROR_WANT_WRITE: {
      ++_statistic._retry_send_data;
      continue;
    }

    case SSL_ERROR_SYSCALL: {
      if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) {
        set_detailed_error(tcp::ssl::fill_error("error occured while send data", err_c));
      } else {
        ++_statistic._retry_send_data;
        continue;
      }
      break;
    }
    default: {
      set_detailed_error(tcp::ssl::fill_error("SSL_write failed", err_c));
      break;
    }
    }
    ++_statistic._failed_send_data;
    break;
  }
  return sent;
}

ssize_t stream::receive(std::byte *buffer, size_t buffer_size) {
  ssize_t rec = -1;
  enable_send_cb();
  while (SSL_get_shutdown(_ctx) == 0) {
    ERR_clear_error();
    rec = SSL_read(_ctx, buffer, buffer_size);
    if (rec > 0) {
      ++_statistic._success_recv_data;
      break;
    }

    int err_c = SSL_get_error(_ctx, rec);
    switch (err_c) {
    case SSL_ERROR_ZERO_RETURN: { /* Received a close_notify alert. */
      set_detailed_error(tcp::ssl::fill_error("ssl read return 0 bytes", err_c));
      break;
    }
    case SSL_ERROR_SYSCALL: {
      if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) {
        set_detailed_error(tcp::ssl::fill_error("error occured while receive ssl data", err_c));
      } else {
        ++_statistic._retry_recv_data;
        continue;
      }
      break;
    }
    case SSL_ERROR_WANT_READ: /* We need more data to finish the frame. */
      return 0;
    case SSL_ERROR_WANT_WRITE: {
      // TODO: Same as in grpc. need to check, maybe it is actual only for boringSSL
      set_detailed_error(tcp::ssl::fill_error("Peer tried to renegotiate SSL connection", err_c));
      break;
    }
    default:
      set_detailed_error(tcp::ssl::fill_error("SSL_read failed", err_c));
      break;
    }
    ++_statistic._failed_recv_data;
    break;
  }
  return rec;
}

} // namespace bro::net::tcp::ssl::send
