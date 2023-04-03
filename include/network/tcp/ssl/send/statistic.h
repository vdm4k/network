#pragma once
#include <network/tcp/send/statistic.h>

namespace bro::net::tcp::ssl::send {
/** @addtogroup tcp_ssl_stream
 *  @{
 */

/**
 * \brief statistic for send stream
 */
struct statistic : public tcp::send::statistic {};
} // namespace bro::net::tcp::ssl::send

/** @} */ // end of tcp_ssl_stream
