#pragma once
#include <network/stream/listen/statistic.h>

namespace bro::net::sctp::listen {
/** @addtogroup sctp_stream
 *  @{
 */

/**
 * \brief statistic for listen stream
 */
struct statistic : public net::listen::statistic {};
} // namespace bro::net::sctp::listen
