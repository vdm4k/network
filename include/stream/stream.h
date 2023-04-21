#pragma once

#include <any>
#include <functional>
#include <memory>
#include <ostream>

#include "settings.h"
#include "statistic.h"

namespace bro::strm {
/** @defgroup stream stream
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
                   ///< get_error_description
  };

  virtual ~stream() = default;

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
  virtual ssize_t send(std::byte const *data, size_t data_size) = 0;

  /*! \brief This function receive data
   *  \param [in] data pointer on a buffer
   *  \param [in] data_size buffer lenght
   *  \return ssize_t 3 options
   *  1. Positive - The number of bytes sent
   *  2. Negative - an error occurred
   *  3. Zero - only if pass zero data_size
   */
  virtual ssize_t receive(std::byte *data, size_t data_size) = 0;

  /*! \brief get detailed description about error
   *  \return error description
   *
   *  \note If happens several errors, will be descriptions about all ocured errors
   */
  virtual std::string const &get_error_description() const = 0;

  /*! \brief get stream state
   *  \return state
   */
  virtual state get_state() const = 0;

  /*! \brief check stream is in active state
   *  \return true if stream is in active state, false otherwise
   *
   *  \note We can't work with inactive state. Nothing bad will happend, but no
   *  data will send on received.
   */
  virtual bool is_active() const = 0;

  /*! \brief set callback on data receive
   *  \param [in] cb callback function.
   *  \param [in] param parameter for callback function
   *
   *  \note If we want to switch off, we will send nullptr as cb
   */
  virtual void set_received_data_cb(received_data_cb cb, std::any param) = 0;

  /*! \brief set callback on state change
   *  \param [in] cb callback function.
   *  \param [in] param parameter for callback function
   *
   *  \note If we want to switch off, we will send nullptr as cb
   */
  virtual void set_state_changed_cb(state_changed_cb cb, std::any param) = 0;

  /*! \brief set callback on data send
   *  \param [in] cb callback function.
   *  \param [in] param parameter for callback function
   *
   *  \note Need set only if using external buffer for sending
   */
  virtual void set_send_data_cb(received_data_cb cb, std::any param) = 0;

  /*! \brief get actual stream settings
   *  \return pointer on actual settings
   *
   *  \note we will always return a pointer on valid settings, hence we can
   *        recreate failed stream with settings from failed stream
   *
   *  \code
   *     stream_ptr failed_stream;
   *     failed_stream =
   *     factory::create_stream(failed_stream->get_settings());
   *  \endcode
   */
  virtual settings const *get_settings() const = 0;

  /*! \brief get actual stream statistic
   *  \return pointer on actual statistic
   *
   *  \note pointer need to cast to specific statistic
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
[[maybe_unused]] static inline char const *state_to_string(stream::state st) {
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
  return out << state_to_string(st);
}

} // namespace bro::strm
