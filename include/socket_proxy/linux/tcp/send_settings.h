#pragma once
#include <protocols/ip/full_address.h>

#include <optional>

#include "settings.h"

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx::tcp {

/*! \class send_stream_socket_parameters
 *  \brief tcp send stream parameters
 */
struct send_stream_parameters : stream_socket_parameters {
  jkl::proto::ip::full_address _peer_addr;  ///< peer address
  std::optional<jkl::proto::ip::full_address>
      _self_addr;  ///< self bind address
};

}  // namespace jkl::sp::lnx::tcp

/** @} */  // end of stream
