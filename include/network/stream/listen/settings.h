#pragma once
#include <network/stream/settings.h>
#include <protocols/ip/full_address.h>
#include <stream/stream.h>

namespace bro::net::listen {
/** @addtogroup network_stream
 *  @{
 */

/*! \brief settings for listen streams
 */
struct settings : net::settings {
  proto::ip::full_address _listen_address;  ///< address for incomming connections
  using in_conn_handler_data_cb = std::any; ///< data type for user data
  using in_conn_handler_cb = std::function<void(bro::strm::stream_ptr &&, in_conn_handler_data_cb)>; ///< callback type
  in_conn_handler_cb _proc_in_conn;              ///< callback for incomming connections
  in_conn_handler_data_cb _in_conn_handler_data; ///< user data
  uint16_t _listen_backlog = 14;                 ///< listen backlog parameter
};

} // namespace bro::net::listen
