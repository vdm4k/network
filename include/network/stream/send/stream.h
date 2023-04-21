#pragma once
#include <libev_wrapper/io.h>
#include <network/common/buffer.h>
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

  /*! \brief This function sends the specified data
   *  \param [in] data pointer on a data to send
   *  \param [in] data_size data lenght
   *  \return ssize_t 3 options
   *  1. Positive - The number of bytes sent
   *  2. Negative - an error occurred
   *  3. Zero - only if pass zero data_size
   *
   *  \note in send we use bufferization, hence we can't send half data
   */
  ssize_t send(std::byte const *data, size_t data_size) override;

  /*! \brief set callback on data receive
   *  \param [in] cb pointer on callback function. If we send
   * nullptr, we switch off handling this type of events
   * \param [in] param parameter for callback function
   */
  void set_received_data_cb(strm::received_data_cb cb, std::any param) override;

  /*! \brief set callback on data send ( don't do anything here )
   *  \param [in] cb callback function.
   *  \param [in] param parameter for callback function
   */
  void set_send_data_cb(strm::received_data_cb cb, std::any param) override;

  /*! brief check if stream in active state
   *  \return bool
   */
  bool is_active() const override;

  /*!
   *  \brief assign event loop to current stream
   *  \param [in] read event controller
   *  \param [in] write event controller
   */
  void assign_events(bro::ev::io_t &&read, bro::ev::io_t &&write);

protected:
  /*! \brief send data using underlying protocol
   *  \param [in] data pointer on a data to send
   *  \param [in] data_size data lenght
   *  \return ssize_t 3 options
   *  1. Positive - The number of bytes sent
   *  2. Negative - an error occurred
   *  3. Zero - only if pass zero data_size
   */
  virtual ssize_t send_data(std::byte const *data, size_t data_size) = 0;

  /*! \brief if connection established succesfully will prepare connection for receiving events
   *  \return true if init complete successful
   */
  virtual bool connection_established();

  /*!
   *  \brief cleanup/free resources (except error message)
   */
  void cleanup() override;

  /*!
   *  \brief turn OFF trigger on ready to send
   */
  void disable_send_cb();

  /*!
   *  \brief turn ON trigger on ready to send
   */
  void enable_send_cb();

private:
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

  bro::ev::io_t _read;                      ///< wait read event
  bro::ev::io_t _write;                     ///< wait write event
  strm::received_data_cb _received_data_cb; ///< receive data callback
  std::any _param_received_data_cb;         ///< user data for receive data callback
  strm::state_changed_cb _state_changed_cb; ///< state change callback
  std::any _param_state_changed_cb;         ///< user data for state change callback
  strm::send_data_cb _send_data_cb;         ///< send data callback
  std::any _param_send_data_cb;             ///< user data for send data callback
  buffer _send_buffer;                      ///< send buffer
  bool _buffer_send{true};                  ///< need to buffer send data
};

} // namespace bro::net::send
