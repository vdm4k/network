#pragma once
#include <network/stream_settings.h>

#include <optional>

namespace bro::net::tcp {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief common settings for listen/send stream
 */
struct stream_settings : public bro::stream_settings {
  std::optional<size_t> _buffer_size;  ///< send/receive buffer size
};

}  // namespace bro::net::tcp

/** @} */  // end of ev_stream
