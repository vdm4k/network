#pragma once
#include <socket_proxy/stream_statistic.h>
#include <stdint.h>

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx::tcp {
struct send_statistic : public stream_statistic {
  uint64_t _send_message;
  uint64_t _send_data;
  uint64_t _receive_message;
  uint64_t _receive_data;
};
}  // namespace jkl::sp::lnx::tcp

/** @} */  // end of stream
