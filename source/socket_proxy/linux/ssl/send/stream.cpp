#include <openssl/err.h>
#include <openssl/ssl.h>
#include <socket_proxy/libev/libev.h>
#include <socket_proxy/linux/ssl/common.h>
#include <socket_proxy/linux/ssl/send/stream.h>

namespace bro::sp::tcp::ssl::send {

stream::~stream() { cleanup(); }

void stream::cleanup() {
  tcp::send::stream::cleanup();
  if (_ctx) {
    SSL_shutdown(_ctx);
    SSL_free(_ctx);
    _ctx = nullptr;
  }

  if (_client_ctx) {
    SSL_CTX_free(_client_ctx);
    _client_ctx = nullptr;
  }
}

bool stream::init(settings *send_params) {
  if (!bro::sp::tcp::send::stream::init(send_params)) return false;
  _settings = *send_params;
  ERR_clear_error();

#if OPENSSL_VERSION_NUMBER >= 0x10100000
  _client_ctx = SSL_CTX_new(TLS_client_method());
#else
  _client_ctx = SSL_CTX_new(TLSv1_2_client_method());
#endif

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
  SSL_CTX_set_options(_client_ctx, ctx_options);
  return true;
}

void stream::connection_established() {
  tcp::send::stream::connection_established();
  if (get_state() != state::e_established) return;
  ERR_clear_error();

  _ctx = SSL_new(_client_ctx);
  SSL_set_fd(_ctx, _file_descr);
  int res = SSL_connect(_ctx);
  res = SSL_get_error(_ctx, res);
  if (res != SSL_ERROR_WANT_READ) {
    set_detailed_error("SSL_connect call: " + ssl_error());
    set_connection_state(state::e_failed);
    cleanup();
  }
}

ssize_t stream::send(std::byte *data, size_t data_size) {
  if (get_state() == state::e_failed) return -1;

  ssize_t sent = -1;
  while (true) {
    ERR_clear_error();
    sent = SSL_write(_ctx, data, data_size);
    if (sent > 0) {
      ++_statistic._success_send_data;
      break;
    }

    int error = SSL_get_error(_ctx, sent);
    switch (error) {
      case SSL_ERROR_WANT_READ:
      case SSL_ERROR_WANT_WRITE: {
        ++_statistic._retry_send_data;
        continue;
      }

      case SSL_ERROR_SYSCALL: {
        if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) {
          set_detailed_error("error occured while send data " + ssl_error());
          set_connection_state(state::e_failed);
        } else {
          ++_statistic._retry_send_data;
          continue;
        }
        break;
      }
      case SSL_ERROR_SSL: {
        set_connection_state(state::e_failed);
        set_detailed_error("SSL_write failed with error " + ssl_error());
        break;
      }
      default: {
        set_connection_state(state::e_failed);
        set_detailed_error("SSL_write failed with error " + ssl_error());
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
  while (true) {
    ERR_clear_error();
    rec = SSL_read(_ctx, buffer, buffer_size);
    if (rec > 0) {
      ++_statistic._success_recv_data;
      break;
    }

    int error = SSL_get_error(_ctx, rec);
    switch (error) {
      case SSL_ERROR_ZERO_RETURN: /* Received a close_notify alert. */ {
        set_detailed_error("ssl read return 0 bytes " + ssl_error());
        set_connection_state(state::e_failed);
        break;
      }
      case SSL_ERROR_SYSCALL: {
        if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) {
          set_detailed_error("error occured while receive ssl data" +
                             ssl_error());
          set_connection_state(state::e_failed);
        } else {
          ++_statistic._retry_recv_data;
          continue;
        }
        break;
      }
      case SSL_ERROR_WANT_READ: /* We need more data to finish the frame. */
        return 0;
      case SSL_ERROR_WANT_WRITE: {
        // TODO: Same as in grpc. need to check, maybe it is actual only for
        // boringSSL
        set_connection_state(state::e_failed);
        set_detailed_error(
            "Peer tried to renegotiate SSL connection. This is unsupported. " +
            ssl_error());
        break;
      }
      case SSL_ERROR_SSL: {
        set_connection_state(state::e_failed);
        set_detailed_error("SSL_read failed with error " + ssl_error());
        break;
      }
      default:
        set_connection_state(state::e_failed);
        set_detailed_error("SSL_read failed with error " + ssl_error());
        break;
    }
    ++_statistic._failed_recv_data;
    break;
  }
  return rec;
}

settings *stream::current_settings() { return &_settings; }

}  // namespace bro::sp::tcp::ssl::send
