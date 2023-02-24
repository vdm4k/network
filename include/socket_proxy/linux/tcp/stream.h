#pragma once
#include <arpa/inet.h>
#include <protocols/ip/full_address.h>
#include <socket_proxy/stream.h>

#include <string>

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx::tcp {

class stream : public jkl::stream {
 public:
  stream() = default;
  stream(stream const &) = delete;
  stream(stream &&) = delete;
  stream &operator=(stream &&) = delete;
  stream &operator=(stream const &) = delete;
  ~stream() override;

  /*! \fn std::string const & get_detailed_error() const
   *  \brief get description about error
   *  \return std::string description
   */
  std::string const &get_detailed_error() const override;

  /*! \fn connection_state get_state() const
   *  \brief socket state
   *  \return connection_state
   */
  state get_state() const override;

  /*! \brief set callback on data receive
   *  \param [in] set_state_changed_cb pointer on callback function if nullptr -
   * non active
   * \param [in] param parameter for callback function
   */
  void set_state_changed_cb(state_changed_cb cb, std::any param) override;

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

/** @} */  // end of stream
