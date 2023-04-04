#pragma once
#include <network/stream/send/statistic.h>

namespace bro::net::udp::send {
/** @addtogroup udp_stream
 *  @{
 */

/**
 * \brief statistic for send stream
 */
struct statistic : public net::send::statistic {};
} // namespace bro::net::udp::send
