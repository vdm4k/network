#pragma once
#include <network/sctp/listen/settings.h>
#include <protocols/ip/full_address.h>

#include <any>
#include <functional>

namespace bro::net::sctp::ssl::listen {
/** @addtogroup ev_stream
 *  @{
 */

/*! \brief sctp receive connections settings
 */
struct settings : sctp::listen::settings {
  std::string _certificate_path;
  std::string _key_path;
  bool _enable_sslv2 = true;
  bool _enable_empty_fragments = false;
  bool _enable_http2 = false;
};

} // namespace bro::net::sctp::ssl::listen

/** @} */ // end of ev_stream
