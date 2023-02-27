#pragma once
#include <protocols/ip/full_address.h>
#include <socket_proxy/linux/tcp/settings.h>
#include <socket_proxy/stream.h>

#include <any>
#include <functional>

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx::tcp::listen {

/*! \class send_stream_socket_parameters
 *  \brief tcp receive connections socket parameters
 */
struct settings : stream_settings {
  jkl::proto::ip::full_address
      _listen_address;  ///< listen incomming connections
  using in_conn_handler_data_cb = std::any;
  using in_conn_handler_cb =
      std::function<void(stream_ptr&&, in_conn_handler_data_cb)>;
  in_conn_handler_cb _proc_in_conn;  ///< incomming connections handler
  in_conn_handler_data_cb _in_conn_handler_data;
  uint16_t _listen_backlog = 14;  ///< listen backlog parameter
};

}  // namespace jkl::sp::lnx::tcp::listen

/** @} */  // end of stream
