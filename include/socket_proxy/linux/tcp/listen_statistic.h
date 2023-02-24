#pragma once
#include <socket_proxy/stream_statistic.h>
#include <stdint.h>

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx::tcp {
struct listen_statistic : public stream_statistic {
  uint64_t _success_accept_connections = 0;
  uint64_t _failed_to_accept_connections = 0;
};
}  // namespace jkl::sp::lnx::tcp

/** @} */  // end of stream
