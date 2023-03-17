#pragma once
#include <protocols/ip/full_address.h>
#include <socket_proxy/linux/tcp/settings.h>
#include <socket_proxy/stream.h>

#include <any>
#include <functional>

namespace bro::sp::tcp::listen {
/** @addtogroup ev_stream
 *  @{
 */

/*! \brief tcp receive connections settings
 */
struct settings : stream_settings {
  bro::proto::ip::full_address
      _listen_address;  ///< address for incomming connections
  using in_conn_handler_data_cb = std::any;  ///< data type for user data
  using in_conn_handler_cb = std::function<void(
      stream_ptr&&, in_conn_handler_data_cb)>;  ///< callback type
  in_conn_handler_cb _proc_in_conn;  ///< callback for incomming connections
  in_conn_handler_data_cb _in_conn_handler_data;  ///< user data
  uint16_t _listen_backlog = 14;                  ///< listen backlog parameter
};

}  // namespace bro::sp::tcp::listen

/** @} */  // end of ev_stream
