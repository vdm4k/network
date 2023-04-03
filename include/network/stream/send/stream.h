#pragma once
#include <network/common/buffer.h>
#include <network/platforms/libev/libev.h>
#include <network/stream/stream.h>

namespace bro::net::listen {
class stream;
} // namespace bro::net::listen

namespace bro::net::send {
/** @addtogroup network_stream
 *  @{
 */

/**
 * \brief send stream
 */
class stream : public net::stream {
public:
  ~stream() override;

  /*! \brief send data
   *  \param [in] data pointer on data
   *  \param [in] data_size data lenght
   *  \return ssize_t if ssize_t is positive - sended data size otherwise
   *  ssize_t interpet as error
   */
  ssize_t send(std::byte const *data, size_t data_size) override;

  /*! \brief set callback on data receive
   *  \param [in] cb pointer on callback function. If we send
   * nullptr, we switch off handling this type of events
   * \param [in] param parameter for callback function
   */
  void set_received_data_cb(strm::received_data_cb cb, std::any param) override;

  /*! brief check if stream in active state
   *  \return bool
   */
  bool is_active() const override;

  /*!
   *  \brief assign event loop to current stream
   *  \param [in] loop pointer on loop
   */
  void assign_loop(struct ev_loop *loop);

protected:
  /*! \brief send data as is
   *  \param [in] cb pointer on callback function. If we send
   * nullptr, we switch off handling this type of events
   * \param [in] param parameter for callback function
   * \param [in] resend - if in resend procedure
   */
  virtual ssize_t send_data(std::byte const *data, size_t data_size) = 0;

  /*!
   *  \brief if connection established prepare internal settings
   *  \return true if init complete successful
   */
  virtual bool connection_established();

  /*!
   *  \brief cleanup/free resources (except error message)
   */
  void cleanup();

  /*!
   *  \brief turn OFF trigger on ready to send
   */
  void disable_send_cb();

  /*!
   *  \brief turn ON trigger on ready to send
   */
  void enable_send_cb();

private:
  friend void connection_established_cb(struct ev_loop *, ev_io *w, int);
  friend void receive_data_cb(struct ev_loop *, ev_io *w, int);
  friend void send_data_cb(struct ev_loop *, ev_io *w, int);

  /*!
   *  \brief stop all events
   */
  void stop_events();

  /*!
   *  \brief process incomming data
   */
  void receive_data();

  /*!
   *  \brief send data from buffer
   */
  void send_buffered_data();

  ev_io _read_io;                           ///< wait read event
  ev_io _write_io;                          ///< wait write event
  struct ev_loop *_loop = nullptr;          ///< pointer on base event loop
  strm::received_data_cb _received_data_cb; ///< receive data callback
  std::any _param_received_data_cb;         ///< user data for receive data callback
  strm::state_changed_cb _state_changed_cb; ///< state change callback
  std::any _param_state_changed_cb;         ///< user data for state change callback
  buffer _send_buffer;                      ///< send buffer
};

} // namespace bro::net::send

/** @} */ // end of network_stream
