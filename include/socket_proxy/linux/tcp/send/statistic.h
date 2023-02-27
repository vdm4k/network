#pragma once
#include <socket_proxy/stream_statistic.h>
#include <stdint.h>

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx::tcp::send {
struct statistic : public stream_statistic {
  uint64_t _success_send_data = 0;
  uint64_t _retry_send_data = 0;
  uint64_t _failed_send_data = 0;
  uint64_t _success_recv_data = 0;
  uint64_t _retry_recv_data = 0;
  uint64_t _failed_recv_data = 0;

  statistic& operator+=(const statistic& rhs) {
    _success_send_data += rhs._success_send_data;
    _retry_send_data += rhs._retry_send_data;
    _failed_send_data += rhs._failed_send_data;
    _success_recv_data += rhs._success_recv_data;
    _retry_recv_data += rhs._retry_recv_data;
    _failed_recv_data += rhs._failed_recv_data;
    return *this;
  }
};
}  // namespace jkl::sp::lnx::tcp::send

/** @} */  // end of stream
