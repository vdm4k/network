#pragma once
#include <network/stream/listen/statistic.h>

namespace bro::net::udp::ssl::listen {
/** @addtogroup udp_stream_stream
 *  @{
 */

/**
 * \brief statistic for listen stream
 */
struct statistic : public net::listen::statistic {};
} // namespace bro::net::udp::ssl::listen
