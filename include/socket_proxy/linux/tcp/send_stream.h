#pragma once
#include <socket_proxy/libev/libev.h>

#include "send_settings.h"
#include "send_statistic.h"
#include "stream.h"

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx::tcp {

class send_stream : public stream {
 public:
  send_stream() = default;
  send_stream(send_stream const &) = delete;
  send_stream(send_stream &&) = delete;
  send_stream &operator=(send_stream &&) = delete;
  send_stream &operator=(send_stream const &) = delete;
  ~send_stream() override;
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
  stream_settings const *get_settings() const override { return &_parameters; }

  /*! \brief get actual stream statistic
   *  \return stream_statistic
   */
  stream_statistic const *get_statistic() const override { return &_statistic; }

  /*! \fn bool is_active() const
   *  \brief check if stream in active state
   *  \return bool
   */
  bool is_active() const override;

  /*!
   *  \brief init send stream
   *  \param [in] send_params pointer on parameters
   *  \param [in] pointer on event loop
   *  \return true if inited. otherwise false (cause in get_detailed_error )
   */
  bool init(send_stream_parameters *send_params);

  void assign_loop(struct ev_loop *loop);

 private:
  friend void connection_established_cb(struct ev_loop *, ev_io *w, int);

  bool connect();
  void stop_events();
  void connection_established();
  void receive_data();
  void send_data();

  friend void receive_data_cb(struct ev_loop *, ev_io *w, int);
  friend void send_data_cb(struct ev_loop *, ev_io *w, int);

  friend class listen_stream;

  struct ev_loop *_loop = nullptr;

  ev_io _read_io;
  ev_io _write_io;
  received_data_cb _received_data_cb;
  std::any _param_received_data_cb;
  send_data_cb _send_data_cb;
  std::any _param_send_data_cb;
  state_changed_cb _state_changed_cb;
  std::any _param_state_changed_cb;

  send_stream_parameters _parameters;
  send_statistic _statistic;
};

}  // namespace jkl::sp::lnx::tcp

/** @} */  // end of stream
