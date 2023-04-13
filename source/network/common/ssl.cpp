#include "openssl/rand.h"
#include <array>
#include <atomic>
#include <network/common/ssl.h>
#include <network/platforms/system.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace bro::net::ssl {

bool set_check_ceritficate(SSL_CTX *ctx, std::string const &cert_path, std::string const &key_path, std::string &err) {
  /* Set the key and cert */
  if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
    err = fill_error("server certificate not found");
    return false;
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
    err = fill_error("key certificate not found");
    return false;
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    err = fill_error("nvalid private key");
    return false;
  }

  /* We won't handle incomplete read/writes due to renegotiation */
  SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);

  /* Specify that we need to verify the server's certificate */
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

  return true;
}

bool set_cipher_list(SSL_CTX *ctx, std::string const &ciphers, std::string &err) {
  if (SSL_CTX_set_cipher_list(ctx, ciphers.c_str()) <= 0) {
    err = fill_error("set cipher list failed");
    return false;
  }
  return true;
}

enum init_state : int {
  e_not_init = 0,
  e_in_progress,
  e_init,
};

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

/*! \brief This function genereate string representation from openssl library
 *  \return filled string if error exist. empty string otherwise
 */
std::string ssl_error() {
  std::string error;
  for (auto err = ERR_get_error(); err != 0; err = ERR_get_error()) {
    char buf[512] = {0};
    ERR_error_string_n(static_cast<uint32_t>(err), buf, sizeof(buf));
    error.append(buf);
  }
  return error;
}

/*! \brief Do the same as ssl_error but add human readable ssl_error_code
  * \param [in] ssl_error_code error code from openSSL
 *  \return filled string if error exist. empty string otherwise
 */
std::string ssl_error(int ssl_error_code) {
  auto res(ssl_error());
  char const *lib = ERR_lib_error_string((unsigned long) ssl_error_code);
  char const *reason = ERR_reason_error_string((unsigned long) ssl_error_code);
  if (lib) {
    if (!res.empty())
      res += "; ";
    res = res + "lib is - " + lib;
  }
  if (reason) {
    if (!res.empty())
      res += "; ";
    res = res + "and the reason is - " + reason;
  }
  return res;
}

std::string fill_error(char const *const err, int ssl_error_code) {
  std::string res;
  if (ssl_error_code) {
    res = ssl_error(ssl_error_code);
  }
  if (!res.empty()) {
    return std::string(err) + "; errors from openSSL " + res;
  }
  return err;
}

std::string fill_error(std::string const &err, int ssl_error_code) {
  std::string res;
  if (ssl_error_code) {
    res = ssl_error(ssl_error_code);
  }
  if (!res.empty()) {
    return std::string(err) + "; errors from openSSL " + res;
  }
  return err;
}

} // namespace bro::net::ssl
