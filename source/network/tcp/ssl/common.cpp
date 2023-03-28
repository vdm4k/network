#include <atomic>
#include <network/tcp/ssl/common.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <mutex>

namespace bro::net::tcp::ssl {

bool check_ceritficate(SSL_CTX *ctx,
                       std::string const &cert_path,
                       std::string const &key_path,
                       std::string &detailed_error) {
  /* Set the key and cert */
  if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
    detailed_error = ("server certificate not found. " + ssl_error());
    return false;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
    std::string err_str(ssl_error());
    detailed_error = ("key certificate not found. " + ssl_error());
    return false;
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    detailed_error = "invalid private key. " + ssl_error();
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
