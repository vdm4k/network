#pragma once
#include <socket_proxy/linux/tcp/send/statistic.h>
#include <stdint.h>

namespace bro::sp::tcp::ssl::send {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief statistic for send stream
 */
struct statistic : public bro::sp::tcp::send::statistic {};
}  // namespace bro::sp::tcp::ssl::send

/** @} */  // end of ev_stream
