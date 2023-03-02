#pragma once
#include <socket_proxy/linux/tcp/listen/statistic.h>
#include <stdint.h>

namespace jkl::sp::tcp::ssl::listen {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief statistic for listen stream
 */
struct statistic : public jkl::sp::tcp::listen::statistic {};
}  // namespace jkl::sp::tcp::ssl::listen

/** @} */  // end of ev_stream
