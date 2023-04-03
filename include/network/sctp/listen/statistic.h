#pragma once
#include <network/stream/listen/statistic.h>

namespace bro::net::sctp::listen {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief statistic for listen stream
 */
struct statistic : public net::listen::statistic {};
} // namespace bro::net::sctp::listen

/** @} */ // end of ev_stream
