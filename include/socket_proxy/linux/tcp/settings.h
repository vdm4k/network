#pragma once
#include <protocols/ip/full_address.h>
#include <socket_proxy/stream.h>
#include <socket_proxy/stream_settings.h>

#include <any>
#include <functional>
#include <optional>

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx::tcp {

struct stream_socket_parameters : public stream_settings {
  std::optional<size_t> _buffer_size;  ///< send/receive buffer size
};

/*! \class send_stream_socket_parameters
 *  \brief tcp send stream parameters
 */
struct send_stream_parameters : stream_socket_parameters {
  jkl::proto::ip::full_address _peer_addr;  ///< peer address
  std::optional<jkl::proto::ip::full_address>
      _self_addr;  ///< self bind address
};

/*! \class send_stream_socket_parameters
 *  \brief tcp receive connections socket parameters
 */
struct listen_stream_parameters : stream_socket_parameters {
  jkl::proto::ip::full_address
      _listen_address;  ///< listen incomming connections
  using in_conn_handler_data_cb = std::any;
  using in_conn_handler_cb =
      std::function<void(stream_ptr&&, in_conn_handler_data_cb)>;
  in_conn_handler_cb _proc_in_conn;  ///< incomming connections handler
  in_conn_handler_data_cb _in_conn_handler_data;
  uint16_t _listen_backlog = 14;  ///< listen backlog parameter
};

}  // namespace jkl::sp::lnx::tcp

/** @} */  // end of stream
