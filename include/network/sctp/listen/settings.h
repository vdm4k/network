#pragma once
#include <network/stream/listen/settings.h>
#include <network/sctp/settings.h>

namespace bro::net::sctp::listen {
/** @addtogroup sctp_stream
 *  @{
 */

/*! \brief sctp receive connections settings
 */
struct settings : sctp::settings, net::listen::settings {};

} // namespace bro::net::sctp::listen

/** @} */ // end of sctp_stream
