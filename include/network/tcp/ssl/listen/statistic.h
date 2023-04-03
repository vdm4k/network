#pragma once
#include <network/tcp/listen/statistic.h>

namespace bro::net::tcp::ssl::listen {
/** @addtogroup tcp_ssl_stream
 *  @{
 */

/**
 * \brief statistic for listen stream
 */
struct statistic : public tcp::listen::statistic {};
} // namespace bro::net::tcp::ssl::listen

/** @} */ // end of tcp_ssl_stream
