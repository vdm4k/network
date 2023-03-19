#pragma once
#include <protocols/ip/full_address.h>
#include <network/linux/tcp/settings.h>

#include <optional>

namespace bro::net::tcp::send {
/** @addtogroup ev_stream
 *  @{
 */

/*!\brief tcp send stream settings
 */
struct settings : stream_settings {
  bro::proto::ip::full_address _peer_addr;                 ///< peer address
  std::optional<bro::proto::ip::full_address> _self_addr;  ///< self address
};

}  // namespace bro::net::tcp::send

/** @} */  // end of ev_stream
