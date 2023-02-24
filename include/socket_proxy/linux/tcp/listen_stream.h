#pragma once
#include <socket_proxy/libev/libev.h>

#include "listen_settings.h"
#include "listen_statistic.h"
#include "stream.h"

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx::tcp {

class listen_stream : public stream {
 public:
  listen_stream() = default;
  listen_stream(listen_stream const &) = delete;
  listen_stream(listen_stream &&) = delete;
  listen_stream &operator=(listen_stream &&) = delete;
  listen_stream &operator=(listen_stream const &) = delete;
  ~listen_stream();

  /*!
   *  \brief couldn't send data in listen stream => always return 0
   *  \param [in] ptr pointer on data
   *  \param [in] len data lenght
   *  \return always return 0
   */
  ssize_t send(std::byte *data, size_t data_size) override;

  /*!
   *  \brief couldn't receive data in listen stream => always return 0
   *  \param [in] ptr pointer on buffer
   *  \param [in] len buffer lenght
   *  \return always return 0
   */
  ssize_t receive(std::byte *data, size_t data_size) override;

  /*! \brief set callback on data receive ( don't do anything )
   *  \param [in] received_data_cb pointer on callback function if nullptr - non
   * active
   * \param [in] param parameter for callback function
   */
  void set_received_data_cb(received_data_cb cb, std::any param) override;

  /*! \brief set callback on data receive ( don't do anything )
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

  /*! \fn faddresses const& get_self_address() const
   *  \brief
   *  \return return self address
   */
  jkl::proto::ip::full_address const &get_self_address() const;

  /*!
   *  \brief init listen stream
   *  \param [in] listen_params pointer on parameters
   *  \param [in] pointer on event loop
   *  \return true if inited. otherwise false (cause in get_detailed_error )
   */
  bool init(listen_stream_parameters *listen_params);

  void assign_loop(struct ev_loop *loop);

 private:
  friend void incoming_connection_cb(struct ev_loop * /*loop*/, ev_io *w,
                                     int /*revents*/);
  void handle_incoming_connection(int file_descr,
                                  proto::ip::full_address const &peer_addr,
                                  proto::ip::full_address const &self_addr);
  bool create_listen_socket();
  void stop_events();

  ev_io _connect_io;
  struct ev_loop *_loop = nullptr;
  listen_stream_parameters _parameters;
  listen_statistic _statistic;
};

}  // namespace jkl::sp::lnx::tcp

/** @} */  // end of stream
