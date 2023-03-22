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
  bool _enable_sslv2 = true;
  bool _enable_empty_fragments = false;
  bool _enable_http2 = false;
};

} // namespace bro::net::sctp::ssl::send

/** @} */ // end of ev_stream
