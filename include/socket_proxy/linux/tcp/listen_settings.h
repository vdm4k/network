#pragma once
#include <protocols/ip/full_address.h>
#include <socket_proxy/stream.h>

#include <any>
#include <functional>

#include "settings.h"

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx::tcp {

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
