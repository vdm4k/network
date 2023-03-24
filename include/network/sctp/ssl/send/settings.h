#pragma once
#include <network/sctp/send/settings.h>
#include <protocols/ip/full_address.h>

#include <optional>

namespace bro::net::sctp::ssl::send {
/** @addtogroup ev_stream
 *  @{
 */

/*!\brief sctp send stream settings
 */
struct settings : sctp::send::settings {
  std::string _certificate_path;
  std::string _key_path;
  bool _enable_sslv2 = true;
  bool _enable_empty_fragments = false;
};

} // namespace bro::net::sctp::ssl::send

/** @} */ // end of ev_stream
