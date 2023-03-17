#pragma once
#include <socket_proxy/linux/tcp/listen/statistic.h>
#include <stdint.h>

namespace bro::sp::tcp::ssl::listen {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief statistic for listen stream
 */
struct statistic : public bro::sp::tcp::listen::statistic {};
}  // namespace bro::sp::tcp::ssl::listen

/** @} */  // end of ev_stream
