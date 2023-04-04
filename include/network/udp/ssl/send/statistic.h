#pragma once
#include <network/udp/send/statistic.h>

namespace bro::net::udp::ssl::send {
/** @addtogroup udp_stream_stream
 *  @{
 */

/**
 * \brief statistic for send stream
 */
struct statistic : public udp::send::statistic {};
} // namespace bro::net::udp::ssl::send
