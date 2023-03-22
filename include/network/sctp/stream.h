#pragma once
#include <network/stream.h>
#include <protocols/ip/full_address.h>

#include <string>

namespace bro::net::sctp {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief common stream for listen/send stream
 */
class stream : public net::stream {
 protected:
  /*! \brief set socket options like send/receive buffers size
   */
  void set_socket_specific_options(
      proto::ip::address::version addr_ver) override;
};

}  // namespace bro::net::sctp

/** @} */  // end of ev_stream
