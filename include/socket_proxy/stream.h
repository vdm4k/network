#pragma once

#include <socket_proxy/stream_settings.h>

#include <any>
#include <functional>
#include <memory>

/** @defgroup stream
 *  @{
 */

namespace jkl {

class stream;

using received_data_cb =
    std::function<void(stream *, std::any)>;  ///< callback on receive data
using send_data_cb =
    std::function<void(stream *, std::any)>;  ///< callback on send data
using state_changed_cb =
    std::function<void(stream *, std::any)>;  ///< callback on state change

class stream {
 public:
  /*!
   * @brief stream state
   */
  enum class state : uint8_t {
    e_closed,       ///< closed - not active
    e_wait,         ///< for server side connection in listen state
                    ///< for client wait establishing with peer
    e_established,  ///< connection established
    e_failed        ///< connection failed, can check error with
                    ///< get_detailed_error
  };

  virtual ~stream() = default;

  /*! \fn send_result send(void const * ptr, size_t len)
   *  \brief send data
   *  \param [in] ptr pointer on data
   *  \param [in] len data lenght
   *  \return send_result if send_result is positive - sended data size
   *      otherwise send_result interpet as error
   */
  virtual ssize_t send(std::byte *data, size_t data_size) = 0;

  /*! \fn receive_result receive(uint8_t *data, size_t size)
   *  \brief receive data
   *  \param [in] ptr pointer on buffer
   *  \param [in] len buffer lenght
   *  \return receive_result if receive_result is positive - received data size
   *      otherwise receive_result interpet as error
   */
  virtual ssize_t receive(std::byte *data, size_t data_size) = 0;

  /*! \fn std::string const & get_detailed_error() const
   *  \brief get description about error
   *  \return std::string error description
   */
  virtual std::string const &get_detailed_error() const = 0;

  /*! \fn connection_state get_state() const
   *  \brief socket state
   *  \return connection_state
   */
  virtual state get_state() const = 0;

  /*! \brief set callback on data receive
   *  \param [in] received_data_cb pointer on callback function if nullptr - non
   * active
   * \param [in] param parameter for callback function
   */
  virtual void set_received_data_cb(received_data_cb cb, std::any param) = 0;

  /*! \brief set callback on data receive
   *  \param [in] send_data_cb pointer on callback function if nullptr - non
   * active
   * \param [in] param parameter for callback function
   */
  virtual void set_send_data_cb(send_data_cb cb, std::any param) = 0;

  /*! \brief set callback on data receive
   *  \param [in] set_state_changed_cb pointer on callback function if nullptr -
   * non active
   * \param [in] param parameter for callback function
   */
  virtual void set_state_changed_cb(state_changed_cb cb, std::any param) = 0;

  /*! \brief get actual stream settings
   *  \return stream_settings
   */
  virtual stream_settings const *get_stream_settings() const = 0;
};

using stream_ptr = std::unique_ptr<stream>;
using proccess_incoming_conn_cb =
    std::function<void(stream_ptr &&new_stream, std::any asoc_data)>;

[[maybe_unused]] static inline const char *connection_state_to_str(
    stream::state st) {
  switch (st) {
    case stream::state::e_closed:
      return "closed";
    case stream::state::e_wait:
      return "wait";
    case stream::state::e_established:
      return "established";
    case stream::state::e_failed:
      return "failed";
    default:
      return "unknown";
  }
}

}  // namespace jkl

/** @} */  // end of stream
