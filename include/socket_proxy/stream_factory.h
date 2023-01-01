#pragma once
#include <protocols/ip_addr.h>
#include <socket_proxy/stream.h>

namespace jkl {
namespace sp {

using in_conn_handler_data_cb = std::any;
using in_conn_handler_cb = std::function<void(in_conn_handler_data_cb)>;

class stream_factory {
 public:
  virtual ~stream_factory() = 0;

  virtual stream_ptr create_send_stream(
      proto::ip_addr const& peer_address) = 0;

  virtual stream_ptr create_listen_stream(
      proto::ip_addr const& self_address, in_conn_handler_cb in_conn_fun_t,
      in_conn_handler_data_cb user_data) = 0;
};

}  // namespace sp
}  // namespace jkl
