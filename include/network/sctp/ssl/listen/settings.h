#pragma once
#include <network/sctp/listen/settings.h>

namespace bro::net::sctp::ssl::listen {
/** @addtogroup sctp_ssl_stream
 *  @{
 */

/*! \brief sctp receive connections settings
 */
struct settings : sctp::listen::settings {
  std::string _certificate_path;
  std::string _key_path;
  bool _enable_sslv2 = true;
  bool _enable_empty_fragments = false;
  bool _need_auth = false;
};

} // namespace bro::net::sctp::ssl::listen

/** @} */ // end of sctp_ssl_stream
