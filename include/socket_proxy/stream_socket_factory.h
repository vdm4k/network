#pragma once
#include <protocols/ip_addr.h>
#include <socket_proxy/stream_socket.h>

namespace jkl {
namespace sp {

using in_conn_user_data_t = void*;
using in_conn_handler_t = void (*)(stream_socket_ptr&& ptr,
                                   in_conn_user_data_t user_data);

class stream_socket_factory {
 public:
  virtual ~stream_socket_factory() = 0;

  virtual stream_socket_ptr init_connection(
      proto::ip_addr const& peer_address) = 0;

  virtual stream_socket_ptr create_listener(proto::ip_addr const& self_address,
                                            in_conn_handler_t in_conn_fun_t,
                                            in_conn_user_data_t user_data) = 0;
};

}  // namespace sp
}  // namespace jkl
