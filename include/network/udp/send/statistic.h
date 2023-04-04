#pragma once
#include <network/stream/send/statistic.h>

namespace bro::net::udp::send {
/** @addtogroup tcp_stream
 *  @{
 */

/**
 * \brief statistic for send stream
 */
struct statistic : public net::send::statistic {};
} // namespace bro::net::udp::send

/** @} */ // end of tcp_stream
