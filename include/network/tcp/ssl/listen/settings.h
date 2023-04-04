#pragma once
#include <network/tcp/listen/settings.h>

namespace bro::net::tcp::ssl::listen {
/** @addtogroup tcp_ssl_stream
 *  @{
 */

/*! \brief tcp receive connections settings
 */
struct settings : tcp::listen::settings {
  std::string _certificate_path;        ///< path to certificate file
  std::string _key_path;                ///< path to key file
  bool _enable_sslv2 = true;            ///< enable sslv2
  bool _enable_empty_fragments = false; ///< enable emplty fragments
  bool _enable_http2 = false;           ///< switch on/off http2 support in ssl
};

} // namespace bro::net::tcp::ssl::listen
