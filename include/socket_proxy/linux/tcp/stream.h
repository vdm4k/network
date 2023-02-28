#pragma once
#include <arpa/inet.h>
#include <protocols/ip/full_address.h>
#include <socket_proxy/stream.h>

#include <string>

namespace jkl::sp::lnx::tcp {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief common stream for listen/send stream
 */
class stream : public jkl::stream {
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

  /*! \brief socket state
   *  \return connection_state
   */
  state get_state() const override;

  /*! \brief set callback on data receive
   *  \param [in] cb pointer on callback function. If we send
   * nullptr, we switch off handling this type of events
   * \param [in] param parameter for callback
   * function
   */
  void set_state_changed_cb(state_changed_cb cb, std::any param) override;

  /*! \brief fill sockaddr_in structure from full address
   * \param [in] faddr full address
   * \param [out] addr filled address
   * \return true on success
   */
  bool fill_sockaddr(jkl::proto::ip::full_address const &faddr,
                     sockaddr_in &addr);

 protected:
  void set_connection_state(state new_state);
  void set_detailed_error(const std::string &str);
  bool create_socket();
  void set_socket_specific_options();
  static bool get_local_address(jkl::proto::ip::address::version ver, int fd,
                                jkl::proto::ip::full_address &addr);
  void cleanup();
  bool bind_on_address(const proto::ip::full_address &self_address);

  int _file_descr = -1;

 private:
  state_changed_cb _state_changed_cb;
  std::any _param_state_changed_cb;
  std::string _detailed_error;
  state _state = state::e_closed;
};

using stream_socket_ptr = std::unique_ptr<stream>;

}  // namespace jkl::sp::lnx::tcp

/** @} */  // end of ev_stream
