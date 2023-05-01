#pragma once
#include <network/tcp/send/settings.h>

namespace bro::net::tcp::ssl::send {
/** @addtogroup tcp_ssl_stream
 *  @{
 */

enum class ssl_version {
  e_ssl_3_0,
  e_tls_1_0,
  e_tls_1_1,
  e_tls_1_2,
  e_tls_1_3,
};

/*!\brief tcp send stream settings
 */
struct settings : tcp::send::settings {
  std::string _certificate_path;           ///< path to certificate file
  std::string _key_path;                   ///< path to key file
  std::string _host_name;                  ///< set host hane
  bool _enable_sslv2 = true;               ///< enable sslv2
  bool _enable_empty_fragments = false;    ///< enable emplty fragments
  bool _enable_http2 = false;              ///< switch on/off http2 support in ssl
  std::optional<ssl_version> _min_version; ///< min tls version
  std::optional<ssl_version> _max_version; ///< max tls version
};

} // namespace bro::net::tcp::ssl::send
