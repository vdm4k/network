#pragma once
#include <network/stream/send/statistic.h>

namespace bro::net::tcp::send {
/** @addtogroup tcp_stream
 *  @{
 */

/**
 * \brief statistic for send stream
 */
struct statistic : public net::send::statistic {};
} // namespace bro::net::tcp::send
