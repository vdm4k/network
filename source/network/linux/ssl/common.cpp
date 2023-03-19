#include <openssl/err.h>
#include <openssl/ssl.h>
#include <network/linux/ssl/common.h>

#include <mutex>

namespace bro::net::tcp::ssl {

void init_openSSL() {
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
  static std::once_flag flag;
  std::call_once(flag, []() {
    const uint64_t flags =
#ifdef OPENSSL_INIT_ENGINE_ALL_BUILTIN
        /* not present in BoringSSL */
        OPENSSL_INIT_ENGINE_ALL_BUILTIN |
#endif
        OPENSSL_INIT_LOAD_CONFIG;
    // first need to init library
    OPENSSL_init_ssl(flags, nullptr);

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    // We don't need this for new version of openSSL
    /* Load error strings into mem*/
    SSL_library_init();
    SSL_load_error_strings(); /* readable error messages */
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
#endif
  });
#endif
  // ssl sctp использует для отправки сообщений sendmsg без флагов
  // => у нас могут появлятся SIGPIPE
  //    signal(SIGPIPE, SIG_IGN);
}

std::string ssl_error() {
  std::string error;
  for (auto err = ERR_get_error(); err != 0; err = ERR_get_error()) {
    char buf[256] = {0};
    ERR_error_string_n(static_cast<uint32_t>(err), buf, sizeof(buf));
    error.append(buf);
  }
  return error;
}
}  // namespace bro::net::tcp::ssl
