#pragma once
#include <network/stream/listen/settings.h>

namespace bro::net::tcp::listen {
/** @addtogroup tcp_stream
 *  @{
 */

/*! \brief tcp receive connections settings
 */
struct settings : net::listen::settings {};

} // namespace bro::net::tcp::listen

/** @} */ // end of tcp_stream
