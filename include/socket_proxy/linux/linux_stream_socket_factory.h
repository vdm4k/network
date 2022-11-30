#pragma once
#include <socket_proxy/stream_socket_factory.h>

namespace jkl::sp::lnx {

class stream_socket_factory : public jkl::sp::stream_socket_factory {
 public:
  ~stream_socket_factory();

  stream_socket_ptr init_connection(
      proto::ip_addr const& peer_address) override;

  stream_socket_ptr create_listener(proto::ip_addr const& self_address,
                                    in_conn_handler_t in_conn_fun_t,
                                    in_conn_user_data_t user_data) override;
};

}  // namespace jkl::sp::lnx
