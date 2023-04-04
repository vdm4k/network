#pragma once
#include <network/sctp/listen/settings.h>

namespace bro::net::sctp::ssl::listen {
/** @addtogroup sctp_ssl_stream
 *  @{
 */

/*! \brief sctp receive connections settings
 */
struct settings : sctp::listen::settings {
  std::string _certificate_path;        ///< path to certificate file
  std::string _key_path;                ///< path to key file
  bool _enable_sslv2 = true;            ///< enable sslv2
  bool _enable_empty_fragments = false; ///< enable emplty fragments
  bool _need_auth = false;              ///< need authorization for incomming streams
};

} // namespace bro::net::sctp::ssl::listen
