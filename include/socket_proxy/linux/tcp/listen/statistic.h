#pragma once
#include <socket_proxy/stream_statistic.h>
#include <stdint.h>

namespace jkl::sp::lnx::tcp::listen {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief statistic for listen stream
 */
struct statistic : public stream_statistic {
  uint64_t _success_accept_connections =
      0;  ///< accepted connection. fully created streams
  uint64_t _failed_to_accept_connections =
      0;  ///< fail to accept connection. reason in stream::get_detailed_error
};
}  // namespace jkl::sp::lnx::tcp::listen

/** @} */  // end of ev_stream
