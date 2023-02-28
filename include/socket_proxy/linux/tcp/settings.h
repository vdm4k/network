#pragma once
#include <socket_proxy/stream_settings.h>

#include <optional>

namespace jkl::sp::lnx::tcp {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief common settings for listen/send stream
 */
struct stream_settings : public jkl::stream_settings {
  std::optional<size_t> _buffer_size;  ///< send/receive buffer size
};

}  // namespace jkl::sp::lnx::tcp

/** @} */  // end of ev_stream
