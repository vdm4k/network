#pragma once
#include <socket_proxy/stream_settings.h>

#include <optional>

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx::tcp {

struct stream_socket_parameters : public stream_settings {
  std::optional<size_t> _buffer_size;  ///< send/receive buffer size
};

}  // namespace jkl::sp::lnx::tcp

/** @} */  // end of stream
