#include "openssl/rand.h"
#include <array>
#include <atomic>
#include <csignal>
#include <network/tcp/ssl/common.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace bro::net::tcp::ssl {

bool set_check_ceritficate(SSL_CTX *ctx, std::string const &cert_path, std::string const &key_path, std::string &err) {
  /* Set the key and cert */
  if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
    err = ("server certificate not found. " + ssl_error());
    return false;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
    std::string err_str(ssl_error());
    err = ("key certificate not found. " + ssl_error());
    return false;
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    err = "invalid private key. " + ssl_error();
    return false;
  }

  /* We won't handle incomplete read/writes due to renegotiation */
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

  /* Specify that we need to verify the server's certificate */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  return true;
}

enum init_state : int {
  e_not_init = 0,
  e_in_progress,
  e_init,
};

bool disable_sig_pipe() {
  // We need this only for openSSL because openSSL send data directly to socket
  // and it doesn't set MSG_NOSIGNAL
  // unfortunately signal(SIGPIPE, SIG_IGN); doesn't work on my Ubuntu 22
  sigset_t sigpipe_mask;
  sigemptyset(&sigpipe_mask);
  sigaddset(&sigpipe_mask, SIGPIPE);
  sigset_t saved_mask;
  return sigprocmask(SIG_BLOCK, &sigpipe_mask, &saved_mask) == 0;
}

enum class cookie_secret : size_t { e_lenght = 16 };

static std::array<unsigned char, (size_t) cookie_secret::e_lenght> secret_cookie;

std::pair<unsigned char *, size_t> get_salt() {
  return {secret_cookie.data(), secret_cookie.size()};
}

static bool init_secret_cookie() {
  return RAND_bytes(secret_cookie.data(), (size_t) cookie_secret::e_lenght) > 0;
}

bool init_openSSL() {
  static bool res{true};
  static std::atomic<init_state> state{e_not_init};
  if (state.load(std::memory_order_acquire) == e_init)
    return res;
  init_state expected{init_state::e_not_init};
  if (!state.compare_exchange_strong(expected, init_state::e_in_progress)) {
    while (state.load(std::memory_order_acquire) != e_init)
      ;
    return res;
  }

  const uint64_t flags =
#ifdef OPENSSL_INIT_ENGINE_ALL_BUILTIN
    OPENSSL_INIT_ENGINE_ALL_BUILTIN |
#endif
    OPENSSL_INIT_LOAD_CONFIG;
  // first need to init library
  res = OPENSSL_init_ssl(flags, nullptr) == 1;

#if OPENSSL_VERSION_NUMBER < 0x30000000L
  // We don't need this for new version of openSSL
  /* Load error strings into mem*/
  SSL_library_init();
  SSL_load_error_strings(); /* readable error messages */
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
#endif

  //NOTE: probably not the best place, but do it here very ease
  res = res && disable_sig_pipe() && init_secret_cookie();
  state.store(init_state::e_init, std::memory_order_release);
  return res;
}

std::string ssl_error() {
  std::string error;
  for (auto err = ERR_get_error(); err != 0; err = ERR_get_error()) {
    char buf[512] = {0};
    ERR_error_string_n(static_cast<uint32_t>(err), buf, sizeof(buf));
    error.append(buf);
  }
  return error;
}
} // namespace bro::net::tcp::ssl
