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
};

} // namespace bro::net::send

/** @} */ // end of network_stream
