#pragma once
#include <network/tcp/send/statistic.h>
#include <stdint.h>

namespace bro::net::tcp::ssl::send {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief statistic for send stream
 */
struct statistic : public tcp::send::statistic {};
}  // namespace bro::net::tcp::ssl::send

/** @} */  // end of ev_stream
