#pragma once
#include <network/stream/send/statistic.h>

namespace bro::net::sctp::send {
/** @addtogroup sctp_stream
 *  @{
 */

/**
 * \brief statistic for send stream
 */
struct statistic : public net::send::statistic {};
} // namespace bro::net::sctp::send
