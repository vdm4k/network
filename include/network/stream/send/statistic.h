#pragma once
#include <stdint.h>
#include <stream/statistic.h>

namespace bro::net::send {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief statistic for send streams
 */
struct statistic : public strm::statistic {
  void reset() override {
    _success_send_data = 0;
    _retry_send_data = 0;
    _failed_send_data = 0;
    _success_recv_data = 0;
    _retry_recv_data = 0;
    _failed_recv_data = 0;
  }

  statistic &operator+=(statistic const &rhs) {
    _success_send_data += rhs._success_send_data;
    _retry_send_data += rhs._retry_send_data;
    _failed_send_data += rhs._failed_send_data;
    _success_recv_data += rhs._success_recv_data;
    _retry_recv_data += rhs._retry_recv_data;
    _failed_recv_data += rhs._failed_recv_data;
    return *this;
  }

  uint64_t _success_send_data = 0; ///< success sended data
  uint64_t _retry_send_data = 0;   ///< retry send
  uint64_t _failed_send_data = 0;  ///< failed to send
  uint64_t _success_recv_data = 0; ///< success receive data
  uint64_t _retry_recv_data = 0;   ///< retry receive
  uint64_t _failed_recv_data = 0;  ///< failed to receive
};
} // namespace bro::net::send

/** @} */ // end of ev_stream
