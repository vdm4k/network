#pragma once
#include <stream/settings.h>

#include <optional>

namespace bro::net {
/** @addtogroup network_stream
 *  @{
 */

/**
 * \brief common settings for listen/send stream
 */
struct settings : public strm::settings {
  std::optional<size_t> _buffer_size;  ///< send/receive buffer size
};

}  // namespace bro::net

/** @} */  // end of network_stream
