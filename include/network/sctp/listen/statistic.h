#pragma once
#include <stdint.h>
#include <stream/statistic.h>

namespace bro::net::sctp::listen {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief statistic for listen stream
 */
struct statistic : public strm::statistic {
  uint64_t _success_accept_connections =
      0;  ///< accepted connection. fully created streams
  uint64_t _failed_to_accept_connections =
      0;  ///< fail to accept connection. reason in stream::get_detailed_error
};
}  // namespace bro::net::sctp::listen

/** @} */  // end of ev_stream
