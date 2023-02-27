#pragma once
#include <protocols/ip/full_address.h>
#include <socket_proxy/linux/tcp/settings.h>

#include <optional>

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx::tcp::send {

/*! \class send_stream_socket_parameters
 *  \brief tcp send stream parameters
 */
struct settings : stream_settings {
  jkl::proto::ip::full_address _peer_addr;  ///< peer address
  std::optional<jkl::proto::ip::full_address>
      _self_addr;  ///< self bind address
};

}  // namespace jkl::sp::lnx::tcp::send

/** @} */  // end of stream
