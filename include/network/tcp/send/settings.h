#pragma once
#include <network/settings.h>
#include <protocols/ip/full_address.h>

#include <optional>

namespace bro::net::tcp::send {
/** @addtogroup ev_stream
 *  @{
 */

/*!\brief tcp send stream settings
 */
struct settings : net::settings {
  proto::ip::full_address _peer_addr;                 ///< peer address
  std::optional<proto::ip::full_address> _self_addr;  ///< self address
};

}  // namespace bro::net::tcp::send

/** @} */  // end of ev_stream
