#pragma once

#include <any>
#include <functional>
#include <memory>
#include <ostream>

#include "settings.h"
#include "statistic.h"

namespace bro::strm {
/** @defgroup stream
 *  @{
 */

class stream;

using received_data_cb = std::function<void(stream *, std::any)>; ///< callback on receive data
using send_data_cb = std::function<void(stream *, std::any)>;     ///< callback on send data
using state_changed_cb = std::function<void(stream *, std::any)>; ///< callback on state change

/**
 * \brief stream interface
 */
class stream {
public:
  /*!
   * @brief stream state
   */
  enum class state : uint8_t {
    e_closed,      ///< closed - not active
    e_wait,        ///< for server side connection in listen state
                   ///< for client side wait for connection with server
    e_established, ///< connection established
    e_failed       ///< connection failed, can check error with
                   ///< get_detailed_error
  };

  virtual ~stream() = default;

  /*! \brief send data
   *  \param [in] data pointer on data
   *  \param [in] data_size data lenght
   *  \return ssize_t if ssize_t is positive - sended data size otherwise
   *  ssize_t interpet as error
   */
  virtual ssize_t send(std::byte *data, size_t data_size) = 0;

  /*! \brief receive data
   *  \param [in] data pointer on buffer
   *  \param [in] data_size buffer lenght
   *  \return ssize_t can be 3 meanings
   *                if positive = received data size
   *                if negative = error ( get_detailed_error )
   */
  virtual ssize_t receive(std::byte *data, size_t data_size) = 0;

  /*! \brief get detailed description about error
   *  \return std::string error description
   */
  virtual std::string const &get_detailed_error() const = 0;

  /*! \brief state
   *  \return connection_state
   */
  virtual state get_state() const = 0;

  /*! \brief check if stream is in active state
   *  \return bool
   */
  virtual bool is_active() const = 0;

  /*! \brief set callback on data receive
   *  \param [in] cb pointer on callback function. If we send
   * nullptr, we switch off handling this type of events
   * \param [in] param parameter for callback function
   */
  virtual void set_received_data_cb(received_data_cb cb, std::any param) = 0;

  /*! \brief set callback on data receive
   *  \param [in] cb pointer on callback function. If we send
   * nullptr, we switch off handling this type of events
   * \param [in] param parameter for callback function
   */
  virtual void set_send_data_cb(send_data_cb cb, std::any param) = 0;

  /*! \brief set callback on data receive
   *  \param [in] cb pointer on callback function. If we send
   * nullptr, we switch off handling this type of events
   * \param [in] param parameter for callback
   * function
   */
  virtual void set_state_changed_cb(state_changed_cb cb, std::any param) = 0;

  /*! \brief get actual stream settings
   *
   *  will always return a pointer on valid settings, hence we can
   *  recreate failed stream with settings from failed stream
   *
   *  example (
   *  stream_ptr failed_stream;
   *  failed_stream =
   * stream_factory::create_stream(failed_stream->get_settings());
   *  )
   *
   * \return * settings
   */
  virtual settings const *get_settings() const = 0;

  /*! \brief get actual stream statistic. need to cast to specific statistic
   *  \return stream_statistic *
   */
  virtual statistic const *get_statistic() const = 0;

  /*! \brief reset actual statistic
   */
  virtual void reset_statistic() = 0;
};

/*!
 * @brief stream pointer type
 */
using stream_ptr = std::unique_ptr<stream>;

/*!
 * @brief convert state to const char * representation
 */
[[maybe_unused]] static inline const char *connection_state_to_str(stream::state st) {
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

/*!
 * \brief print state in out stream
 * \return std::ostream
 */
inline std::ostream &operator<<(std::ostream &out, stream::state st) {
  return out << connection_state_to_str(st);
}

} // namespace bro::strm

/** @} */ // end of stream
