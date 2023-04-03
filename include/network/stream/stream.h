#pragma once
#include <protocols/ip/full_address.h>
#include <network/platforms/system.h>
#include <stream/stream.h>

namespace bro::net::listen {
class stream;
} // namespace bro::net::listen

namespace bro::net {
/** @defgroup network_stream
 *  @{
 */

/**
 * \brief This class common for all listen and send streams.
 *        Here we process create/delete socket and error handling.
 */
class stream : public strm::stream {
public:
  /**
   * \brief default constructor
   */
  stream() = default;

  /**
   * \brief disabled copy ctor
   *
   * Can be too complex
   */
  stream(stream const &) = delete;

  /**
   * \brief disabled move ctor
   *
   * Can be too complex
   */
  stream(stream &&) = delete;

  /**
   * \brief disabled move assign operator
   *
   * Can be too complex
   */
  stream &operator=(stream &&) = delete;

  /**
   * \brief disabled assign operator
   *
   * Can be too complex
   */
  stream &operator=(stream const &) = delete;

  ~stream() override;

  /*! \brief get detailed description about error
   *  \return std::string error description
   */
  std::string const &get_detailed_error() const override;

  /*! \brief state
   *  \return connection_state
   */
  state get_state() const override;

  /*! \brief set callback on data receive
   *  \param [in] cb pointer on callback function. If we send
   * nullptr, we switch off handling this type of events
   * \param [in] param parameter for callback
   * function
   */
  void set_state_changed_cb(strm::state_changed_cb cb, std::any param) override;

protected:
  /*! \brief create new socket
   */
  [[nodiscard]] virtual bool create_socket(proto::ip::address::version version, socket_type s_type);

  /*! \brief set base socket options
   */
  [[nodiscard]] bool set_socket_options();

  /*! \brief set state for stream
   * \param [in] new_state new state
   */
  void set_connection_state(state new_state);

  /*! \brief set detailed error for stream
   * \param [in] err error description
   */
  void set_detailed_error(std::string const &err);

  /*! \brief set detailed error for stream
   * \param [in] err error description
   */
  void set_detailed_error(char const *const err);

  std::string &get_detailed_error();

  /*! \brief cleanup current stream
   */
  void cleanup();

  int _file_descr = -1; ///< file descriptor

private:
  friend class bro::net::listen::stream;

  strm::state_changed_cb _state_changed_cb; ///< state changed callback
  std::any _param_state_changed_cb;         ///< user data for state changed callback
  std::string _err;                         ///< error description ( if set error )
  state _state = state::e_closed;           ///< current state
};

} // namespace bro::net

/** @} */ // end of network_stream
