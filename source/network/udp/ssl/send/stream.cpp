#include <network/udp/ssl/send/stream.h>
#include <network/tcp/ssl/common.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace bro::net::udp::ssl::send {

stream::~stream() {
  cleanup();
}

void stream::cleanup() {
  if (_client_ctx) {
    SSL_CTX_free(_client_ctx);
    _client_ctx = nullptr;
  }

  if (_ctx) {
    SSL_shutdown(_ctx);
    SSL_free(_ctx);
    _ctx = nullptr;
  }

  if (_bio) {
    BIO_free_all(_bio);
    _bio = nullptr;
  }
  net::send::stream::cleanup();
}

bool stream::init(settings *send_params) {
  if (!tcp::ssl::init_openSSL()) {
    set_detailed_error("coulnd't init ssl library " + tcp::ssl::ssl_error());
    set_connection_state(state::e_failed);
    cleanup();
    return false;
  }
  _settings = *send_params;

  if (!create_socket(_settings._peer_addr.get_address().get_version(), socket_type::e_udp))
    return false;
  ERR_clear_error();

  _client_ctx = SSL_CTX_new(DTLS_client_method());

  if (!_client_ctx) {
    set_detailed_error("couldn't create client_ctx: " + tcp::ssl::ssl_error());
    set_connection_state(state::e_failed);
    cleanup();
    return false;
  }

  unsigned long ctx_options = SSL_OP_ALL;

#ifdef SSL_OP_NO_TICKET
  ctx_options |= SSL_OP_NO_TICKET;
#endif

#ifdef SSL_OP_NO_COMPRESSION
  ctx_options |= SSL_OP_NO_COMPRESSION;
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

  //NOTE: probably we can check return mask, but I don't see why we need it and how to handle it
  SSL_CTX_set_options(_client_ctx, ctx_options);

  if (!_settings._certificate_path.empty() && !_settings._key_path.empty()) {
    if (!tcp::ssl::set_check_ceritficate(_client_ctx,
                                         _settings._certificate_path,
                                         _settings._key_path,
                                         get_error_description())) {
      set_connection_state(state::e_failed);
      cleanup();
      return false;
    }
    SSL_CTX_set_verify_depth(_client_ctx, 2);
  }

  _ctx = SSL_new(_client_ctx);
  if (!_ctx) {
    set_detailed_error("couldn't create ssl ctx: " + tcp::ssl::ssl_error());
    set_connection_state(state::e_failed);
    cleanup();
    return false;
  }

  /* Create DTLS/SCTP BIO and connect */
  _bio = BIO_new_dgram(get_fd(), BIO_NOCLOSE);

  if (!_bio) {
    set_detailed_error("couldn't create bio: " + tcp::ssl::ssl_error());
    set_connection_state(state::e_failed);
    cleanup();
    return false;
  }

  if (!connect()) {
    cleanup();
    return false;
  }
  set_connection_state(state::e_wait);
  return true;
}

bool stream::connection_established() {
  if (!net::send::stream::connection_established()) {
    cleanup();
    return false;
  }
  ERR_clear_error();

  auto remote_addr = _settings._peer_addr.get_address().to_native_v4();

  if (0 >= BIO_ctrl(_bio, BIO_CTRL_DGRAM_SET_CONNECTED, 0, &remote_addr)) {
    set_detailed_error("Bio ctrl call failed with error for BIO_CTRL_DGRAM_SET_CONNECTED: " + tcp::ssl::ssl_error());
    set_connection_state(state::e_failed);
    cleanup();
    return false;
  }

  // SSL_set_bio() takes ownership of _bio
  SSL_set_bio(_ctx, _bio, _bio);
  _bio = nullptr;
  int retval = SSL_connect(_ctx);
  if (retval <= 0) {
    retval = SSL_get_error(_ctx, retval);
    if (retval != SSL_ERROR_WANT_READ) {
      set_detailed_error("SSL_connect call: " + tcp::ssl::ssl_error());
      set_connection_state(state::e_failed);
      cleanup();
      return false;
    }
  }

  if (_settings._recieve_timeout) {
    struct timeval timeout;
    timeout.tv_sec = std::chrono::duration_cast<std::chrono::seconds>(*_settings._recieve_timeout).count();
    timeout.tv_usec = std::chrono::microseconds(*_settings._recieve_timeout).count();
    if (0 >= BIO_ctrl(_bio, BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout)) {
      set_detailed_error("Bio ctrl call failed with error for BIO_CTRL_DGRAM_SET_RECV_TIMEOUT: "
                         + tcp::ssl::ssl_error());
      set_connection_state(state::e_failed);
      cleanup();
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

    int error = SSL_get_error(_ctx, sent);
    switch (error) {
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
        set_detailed_error("error occured while send data " + tcp::ssl::ssl_error());
        set_connection_state(state::e_failed);
      } else {
        ++_statistic._retry_send_data;
        continue;
      }
      break;
    }
    default: {
      set_connection_state(state::e_failed);
      set_detailed_error("SSL_write failed with error " + tcp::ssl::ssl_error());
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

    int error = SSL_get_error(_ctx, rec);
    switch (error) {
    case SSL_ERROR_ZERO_RETURN: { /* Received a close_notify alert. */
      set_detailed_error("ssl read return 0 bytes " + tcp::ssl::ssl_error());
      set_connection_state(state::e_failed);
      break;
    }
    case SSL_ERROR_SYSCALL: {
      if (EAGAIN != errno && EWOULDBLOCK != errno && EINTR != errno) {
        set_detailed_error("error occured while receive ssl data" + tcp::ssl::ssl_error());
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
      // TODO: Same as in grpc. need to check, maybe it is actual only for boringSSL
      set_connection_state(state::e_failed);
      set_detailed_error("Peer tried to renegotiate SSL connection. This is unsupported. " + tcp::ssl::ssl_error());
      break;
    }
    case SSL_ERROR_SSL: {
      set_connection_state(state::e_failed);
      set_detailed_error("SSL_read failed with error " + tcp::ssl::ssl_error());
      break;
    }
    default:
      set_connection_state(state::e_failed);
      set_detailed_error("SSL_read failed with error " + tcp::ssl::ssl_error());
      break;
    }
    ++_statistic._failed_recv_data;
    break;
  }
  return rec;
}

} // namespace bro::net::udp::ssl::send
