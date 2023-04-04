#pragma once
#include <network/sctp/send/settings.h>

namespace bro::net::sctp::ssl::send {
/** @addtogroup sctp_ssl_stream
 *  @{
 */

/*!\brief sctp send stream settings
 */
struct settings : sctp::send::settings {
  std::string _certificate_path;        ///< path to certificate file
  std::string _key_path;                ///< path to key file
  bool _enable_sslv2 = true;            ///< enable sslv2
  bool _enable_empty_fragments = false; ///< enable emplty fragments
};

} // namespace bro::net::sctp::ssl::send
