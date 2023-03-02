#pragma once
#include <protocols/ip/full_address.h>
#include <socket_proxy/linux/tcp/settings.h>

#include <optional>

namespace jkl::sp::tcp::send {
/** @addtogroup ev_stream
 *  @{
 */

/*!\brief tcp send stream settings
 */
struct settings : stream_settings {
  jkl::proto::ip::full_address _peer_addr;                 ///< peer address
  std::optional<jkl::proto::ip::full_address> _self_addr;  ///< self address
};

}  // namespace jkl::sp::tcp::send

/** @} */  // end of ev_stream
