#pragma once
#include <network/tcp/send/settings.h>

namespace bro::net::tcp::ssl::send {
/** @addtogroup tcp_ssl_stream
 *  @{
 */

/*!\brief tcp send stream settings
 */
struct settings : tcp::send::settings {
  std::string _certificate_path;
  std::string _key_path;
  bool _enable_sslv2 = true;
  bool _enable_empty_fragments = false;
  bool _enable_http2 = false;
};

} // namespace bro::net::tcp::ssl::send

/** @} */ // end of tcp_ssl_stream
