#pragma once
#include <stdint.h>
#include <stream/statistic.h>

namespace bro::net::listen {
/** @addtogroup network_stream
 *  @{
 */

/**
 * \brief statistic for listen streams
 */
struct statistic : public strm::statistic {
  /*! \brief reset statistics
   */
  void reset() override {
    _success_accept_connections = 0;
    _failed_to_accept_connections = 0;
  }
  uint64_t _success_accept_connections = 0;   ///< accepted connection. fully created streams
  uint64_t _failed_to_accept_connections = 0; ///< fail to accept connection. reason in stream::get_error_description
};
} // namespace bro::net::listen

/** @} */ // end of network_stream
