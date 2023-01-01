#pragma once
#include <socket_proxy/stream_factory.h>

namespace jkl::sp::lnx {

class stream_factory : public jkl::sp::stream_factory {
 public:
  ~stream_factory();

  stream_ptr create_send_stream(
      proto::ip_addr const& peer_address) override;

  stream_ptr create_listen_stream(
      proto::ip_addr const& self_address, in_conn_handler_cb in_conn_fun_t,
      in_conn_handler_data_cb user_data) override;
};

}  // namespace jkl::sp::lnx
