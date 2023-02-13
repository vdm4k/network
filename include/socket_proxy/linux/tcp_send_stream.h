#pragma once
#include <socket_proxy/libev/libev.h>
#include <socket_proxy/linux/tcp_settings.h>

#include "tcp_stream.h"

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx {

class tcp_send_stream : public tcp_stream {
 public:
  tcp_send_stream() = default;
  tcp_send_stream(tcp_send_stream const &) = delete;
  tcp_send_stream(tcp_send_stream &&) = delete;
  tcp_send_stream &operator=(tcp_send_stream &&) = delete;
  tcp_send_stream &operator=(tcp_send_stream const &) = delete;
  ~tcp_send_stream() override;
  /*! \fn send_result send(void const * ptr, size_t len)
   *  \brief send data
   *  \param [in] ptr pointer on data
   *  \param [in] len data lenght
   *  \return send_result if send_result is positive - sended data size
   *      otherwise send_result interpet as error
   */
  ssize_t send(std::byte *data, size_t data_size) override;

  /*! \fn receive_result receive(uint8_t *data, size_t size)
   *  \brief receive data
   *  \param [in] ptr pointer on buffer
   *  \param [in] len buffer lenght
   *  \return receive_result if receive_result is positive - received data size
   *      otherwise receive_result interpet as error
   */
  ssize_t receive(std::byte *data, size_t data_size) override;

  /*! \fn faddresses const& get_peer_address() const
   *  \brief
   *  \return return peer address
   */
  jkl::proto::ip::full_address const &get_peer_address() const;

  /*! \brief set callback on data receive
   *  \param [in] received_data_cb pointer on callback function if nullptr - non
   * active
   * \param [in] param parameter for callback function
   */
  void set_received_data_cb(received_data_cb cb, std::any param) override;

  /*! \brief set callback on data receive
   *  \param [in] send_data_cb pointer on callback function if nullptr - non
   * active
   * \param [in] param parameter for callback function
   */
  void set_send_data_cb(send_data_cb cb, std::any param) override;

  /*! \brief get actual stream settings
   *  \return stream_settings
   */
  stream_settings const *get_stream_settings() const override {
    return &_send_stream_socket_parameters;
  }

  /*!
   *  \brief init send stream
   *  \param [in] send_params pointer on parameters
   *  \param [in] pointer on event loop
   *  \return true if inited. otherwise false (cause in get_detailed_error )
   */
  bool init(send_stream_socket_parameters *send_params, struct ev_loop *loop);

 private:
  friend void connection_established_cb(struct ev_loop *, ev_io *w, int);

  void init_events(struct ev_loop *loop);
  bool connect();
  void stop_events();
  void connection_established();
  void receive_data();
  void send_data();
  void set_socket_specific_options();

  friend void receive_data_cb(struct ev_loop *, ev_io *w, int);
  friend void send_data_cb(struct ev_loop *, ev_io *w, int);

  friend class tcp_listen_stream;

  struct ev_loop *_loop = nullptr;
  sockaddr_in _peer_addr;
  ev_io _connect_io;
  ev_io _read_io;
  ev_io _write_io;
  std::string _error;
  received_data_cb _received_data_cb;
  std::any _param_received_data_cb;
  send_data_cb _send_data_cb;
  std::any _param_send_data_cb;
  state_changed_cb _state_changed_cb;
  std::any _param_state_changed_cb;

  jkl::proto::ip::full_address _peer_addr_full;
  state _state = state::e_closed;
  send_stream_socket_parameters _send_stream_socket_parameters;

  sockaddr_in _self_addr;
  std::string _detailed_error;
};

}  // namespace jkl::sp::lnx

/** @} */  // end of stream
