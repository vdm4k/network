#pragma once
#include <network/libev/libev.h>
#include <network/sctp/stream.h>

#include "settings.h"
#include "statistic.h"

namespace bro::net::sctp::listen {
class stream;
} // namespace bro::net::sctp::listen

namespace bro::net::sctp::send {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief send stream
 */
class stream : public sctp::stream {
public:
  ~stream() override;

  /*! \brief send data
   *  \param [in] data pointer on data
   *  \param [in] data_size data lenght
   *  \return ssize_t if ssize_t is positive - sended data size otherwise
   *  ssize_t interpet as error
   */
  ssize_t send(std::byte *data, size_t data_size) override;

  /*! \brief receive data
   *  \param [in] data pointer on buffer
   *  \param [in] data_size buffer lenght
   *  \return ssize_t if ssize_t is positive - received data size otherwise
   * ssize_t interpet as error
   */
  ssize_t receive(std::byte *data, size_t data_size) override;

  /*! \brief set callback on data receive
   *  \param [in] cb pointer on callback function. If we send
   * nullptr, we switch off handling this type of events
   * \param [in] param parameter for callback function
   */
  void set_received_data_cb(strm::received_data_cb cb, std::any param) override;

  /*! \brief set callback on data receive
   *  \param [in] cb pointer on callback function. If we send
   * nullptr, we switch off handling this type of events
   * \param [in] param parameter for callback function
   */
  void set_send_data_cb(strm::send_data_cb cb, std::any param) override;

  /*! \brief get actual stream settings
   *  \return settings
   */
  settings const *get_settings() const override { return &_settings; }

  /*! \brief get actual stream statistic
   *  \return stream_statistic
   */
  statistic const *get_statistic() const override { return &_statistic; }

  /*! \brief reset actual statistic
   */
  void reset_statistic() override;

  /*! brief check if stream in active state
   *  \return bool
   */
  bool is_active() const override;

  /*!
   *  \brief init send stream
   *  \param [in] send_params pointer on parameters
   *  \return true if inited. otherwise false (cause in get_detailed_error )
   */
  bool init(settings *send_params);

  /*!
   *  \brief assign event loop to current stream
   *  \param [in] loop pointer on loop
   */
  void assign_loop(struct ev_loop *loop);

protected:
  virtual void connection_established();

  void cleanup();

private:
  friend void connection_established_cb(struct ev_loop *, ev_io *w, int);
  virtual settings *current_settings();

  bool connect();
  void stop_events();
  void receive_data();
  void send_data();

  friend void receive_data_cb(struct ev_loop *, ev_io *w, int);
  friend void send_data_cb(struct ev_loop *, ev_io *w, int);

  friend class bro::net::sctp::listen::stream;

  ev_io _read_io;                           ///< wait read event
  ev_io _write_io;                          ///< wait write event
  struct ev_loop *_loop = nullptr;          ///< pointer on base event loop
  strm::received_data_cb _received_data_cb; ///< receive data callback
  std::any _param_received_data_cb; ///< user data for receive data callback
  strm::send_data_cb _send_data_cb; ///< send data callback
  std::any _param_send_data_cb;     ///< user data for send data callback
  strm::state_changed_cb _state_changed_cb; ///< state change callback
  std::any _param_state_changed_cb; ///< user data for state change callback
  settings _settings;               ///< current settings
  statistic _statistic;             ///< statistics
};

} // namespace bro::net::sctp::send

/** @} */ // end of ev_stream
