#pragma once
#include <network/tcp/listen/statistic.h>
#include <stdint.h>

namespace bro::net::tcp::ssl::listen {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief statistic for listen stream
 */
struct statistic : public tcp::listen::statistic {};
}  // namespace bro::net::tcp::ssl::listen

/** @} */  // end of ev_stream
