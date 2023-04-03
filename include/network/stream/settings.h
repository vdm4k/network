#pragma once
#include <stream/settings.h>
#include <optional>

namespace bro::net {
/** @addtogroup network_stream
 *  @{
 */

/**
 * \brief common settings for both listen and send streams
 */
struct settings : public strm::settings {
  std::optional<size_t> _buffer_size; ///< send/receive buffer size
  bool _non_blocking_socket = true;   ///< use non blocking socket
};

} // namespace bro::net

/** @} */ // end of network_stream
