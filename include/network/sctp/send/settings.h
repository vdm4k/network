#pragma once
#include <network/sctp/settings.h>
#include <network/stream/send/settings.h>

namespace bro::net::sctp::send {
/** @addtogroup sctp_stream
 *  @{
 */

/*!\brief sctp send stream settings
 */
struct settings : sctp::settings, net::send::settings {};

} // namespace bro::net::sctp::send

/** @} */ // end of sctp_stream
