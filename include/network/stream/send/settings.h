#pragma once
#include <optional>
#include <network/stream/settings.h>
#include <protocols/ip/full_address.h>

namespace bro::net::send {
/** @addtogroup network_stream
 *  @{
 */

/*!\brief setting for send streams
 */
struct settings : net::settings {
  proto::ip::full_address _peer_addr;                ///< peer address
  std::optional<proto::ip::full_address> _self_addr; ///< self address
  bool _buffer_send{true}; ///< if couldn't send all with one send call, will buffer and send parts.
                           ///< If it fallse caller must check return size carefully ( actual for extenal buffer >
};

} // namespace bro::net::send
