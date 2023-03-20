#pragma once
#include <arpa/inet.h>
#include <protocols/ip/full_address.h>
#include <stream/stream.h>

#include <string>

namespace bro::net::sctp {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief common stream for listen/send stream
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
  void set_state_changed_cb(strm::state_changed_cb cb,
                            std::any param) override;

  /*! \brief fill sockaddr_in structure from full address
   * \param [in] faddr full address
   * \param [out] addr filled address
   * \return true on success
   */
  bool fill_sockaddr(proto::ip::full_address const &faddr, sockaddr_in &addr);

 protected:
  /*! \brief set state for stream
   * \param [in] new_state new state
   */
  void set_connection_state(state new_state);

  /*! \brief set detailed error for stream
   * \param [in] err error description
   */
  void set_detailed_error(const std::string &err);

  /*! \brief create new socket
   */
  bool create_socket();

  /*! \brief set socket options like send/receive buffers size
   */
  void set_socket_specific_options();

  /*! \brief get ip address for active file descriptor
   * \param [in] ver version of ip protocol
   * \param [in] fd file descriptor
   * \param [out] addr address to fill
   * \result true if success
   */
  static bool get_local_address(proto::ip::address::version ver, int fd,
                                proto::ip::full_address &addr);

  /*! \brief cleanup current stream
   */
  void cleanup();

  /*! \brief bind current stream on specific address
   *  \param [in] self_address address to bind
   *  \result true if success
   */
  bool bind_on_address(const proto::ip::full_address &self_address);

  int _file_descr = -1;  ///< file descriptor

 private:
  strm::state_changed_cb _state_changed_cb;  ///< state changed callback
  std::any _param_state_changed_cb;  ///< user data for state changed callback
  std::string _detailed_error;       ///< error description ( if set error )
  state _state = state::e_closed;    ///< current state
};

}  // namespace bro::net::sctp

/** @} */  // end of ev_stream
