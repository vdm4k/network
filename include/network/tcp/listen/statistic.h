#pragma once
#include <network/stream/listen/statistic.h>

namespace bro::net::tcp::listen {
/** @addtogroup tcp_stream
 *  @{
 */

/**
 * \brief statistic for listen stream
 */
struct statistic : public net::listen::statistic {};
} // namespace bro::net::tcp::listen

/** @} */ // end of tcp_stream
