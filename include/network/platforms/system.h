#pragma once
#include <protocols/ip/full_address.h>
#ifdef WITH_SCTP
#include <network/sctp/settings.h>
#endif

namespace bro::net {

/** @defgroup platforms platforms
 *  @{
 */

/*! \brief This function disable sigpipe generation for whole process
 *  \return  true on succes. false otherwise and err will filled with error
 *
 *  \note better to call before start other threads ( from main thread )
 */
bool disable_sig_pipe();

/*!
   * @brief stream type
   */
enum class socket_type : uint8_t {
  e_tcp,  ///< tcp socket
  e_sctp, ///< sctp socket
  e_udp   ///< udp socket
};

/*! \brief This function creates a string containing an error message from err and errno ( if set )
 * \param [in] err A pointer to a null-terminated string containing the error message.
 * \result A string containing the error message
 *
 * \note we set errno to zero in this function
 */
std::string fill_error(char const *const err);

/*! \brief This function creates a string containing an error message from err and errno ( if set )
 * \param [in] err A string with error message.
 * \result A string containing the error message
 *
 * \note we set errno to zero in this function
 */
std::string fill_error(std::string const &err);

/*! \brief  Appends an error message to an existing error string.
 * \param [in] to A reference to the string to which the error message will be appended.
 * \param [in] new_err A const reference to the string containing the new error message to be added.
 */
void append_error(std::string &to, std::string const &new_err);

/*! \brief  Appends an error message to an existing error string.
 * \param [in] to A reference to the string to which the error message will be appended.
 * \param [in] new_err A const pointer to a null-terminated string containing the new error message to be added.
 */
void append_error(std::string &to, char const *const new_err);

/*! \brief get ip address from file descriptor
 * \param [in] ver - ip protocol version
 * \param [in] file_descr - file descriptor
 * \result filled full_address on success. nullopt otherwise
 *
 * \warning file_descr must be socket
 */
std::optional<proto::ip::full_address> get_address_from_file_descr(proto::ip::address::version ver, int file_descr);

/*! \brief get ip address from file descriptor
 * \param [in] ver - ip protocol version
 * \param [in] file_descr - file descriptor
 * \param [out] err - will fill with error if something go wrong
 * \result filled full_address
 *
 * \warning file_descr must be socket
 */
proto::ip::full_address get_address_from_file_descr(proto::ip::address::version ver, int file_descr, std::string &err);

/*! \brief bind file_descr(socket) on self address
 *  \param [in] self_address address to bind
 *  \param [in] file_descr - file descriptor
 *  \param [out] err - will fill with error if something go wrong
 *  \result true on succes. false otherwise and err will filled with error
 */
[[nodiscard]] bool bind_on_address(proto::ip::full_address &self_address, int file_descr, std::string &err);

/*!
  * @brief all necessary data about connection
  */
struct accept_connection_details {
  proto::ip::full_address _peer_addr;    ///< peer address
  proto::ip::full_address _self_address; ///< self address
  int _client_fd;                        ///< file descriptor of current connection
};

using accept_connection_res
  = std::optional<accept_connection_details>; ///< result of accept_connection function. filled on success

/*! \brief create new connection with peer
 *  \param [in] server_fd server file descriptor ( on which we listen incomming connections )
 *  \param [in] ver - ip protocol version
 *  \param [out] err - will fill with error if something go wrong
 *  \result filled accept_connection_details on succes. nullopt otherwise
 */
[[nodiscard]] accept_connection_res accept_connection(proto::ip::address::version ver, int server_fd, std::string &err);

/*! \brief connect with peer
 *  \param [in] peer_addr - peer address
 *  \param [in] file_descr  -  self file descriptor
 *  \param [out] err - will fill with error if something go wrong
 *  \result true on succes. false otherwise and err will filled with error
 */
[[nodiscard]] bool connect_stream(proto::ip::full_address const &peer_addr, int file_descr, std::string &err);

/*! \brief enable reuse address
 *  \param [in] file_descr  -  self file descriptor
 *  \param [out] err - will fill with error if something go wrong
 *  \result true on succes. false otherwise and err will filled with error
 */
[[nodiscard]] bool reuse_address(int file_descr, std::string &err);

/*! \brief start listen incomming connections on socket (file_descr)
 *  \param [in] file_descr  -  self file descriptor
 *  \param [in] listen_backlog  -  maximum rate at which a server can accept new connections
 *  \param [out] err - will fill with error if something go wrong
 *  \result true on succes. false otherwise and err will filled with error
 */
[[nodiscard]] bool start_listen(int file_descr, int listen_backlog, std::string &err);

/*! \brief create new socket (file_descr)
 *  \param [in] ver - ip protocol version
 *  \param [in] s_type - socket type
 *  \param [out] err - will fill with error if something go wrong
 *  \result filled file descriptor on succes. nullopt otherwise
 */
[[nodiscard]] std::optional<int> create_socket(proto::ip::address::version ver, socket_type s_type, std::string &err);

/*! \brief close socket (file_descr)
 *  \param [in] file_descr  -  self file descriptor
 *  \param [out] err - will fill with error if something go wrong
 *  \result true on succes. false otherwise and err will filled with error
 */
bool close_socket(int &file_descr, std::string &err);

/*! \brief set non blocking mode on socket (file_descr)
 *  \param [in] file_descr - file descriptor
 *  \param [out] err - will fill with error if something go wrong
 *  \result true on succes. false otherwise and err will filled with error
 */
[[nodiscard]] bool set_non_blocking_mode(int file_descr, std::string &err);

/*! \brief set socket buffer size (both - in and out)
 *  \param [in] file_descr - file descriptor
 *  \param [in] buffer_size - socket buffer size
 *  \param [out] err - will fill with error if something go wrong
 *  \result true on succes. false otherwise and err will filled with error
 */
[[nodiscard]] bool set_socket_buffer_size(int file_descr, int buffer_size, std::string &err);

/*! \brief set tcp specific options
 *  \param [in] file_descr - file descriptor
 *  \param [out] err - will fill with error if something go wrong
 *  \result true on succes. false otherwise and err will filled with error
 */
bool set_tcp_options(int file_descr, std::string &err);

/*! \brief check connection established succesfully
 *  \param [in] file_descr - file descriptor
 *  \param [out] err - will fill with error if something go wrong
 *  \result true on succes. false otherwise and err will filled with error
 */
[[nodiscard]] bool is_connection_established(int file_descr, std::string &err);

#ifdef WITH_SCTP

/*! \brief bind sctp file_descr(socket) on self address
 *  \param [in] self_address address to bind
 *  \param [in] file_descr - file descriptor
 *  \param [out] err - will fill with error if something go wrong
 *  \result true on succes. false otherwise and err will filled with error
 */
[[nodiscard]] bool bind_on_sctp_address(proto::ip::full_address &self_address, int file_descr, std::string &err);

/*! \brief bind sctp asconf
 *  \param [in] file_descr - file descriptor
 *  \param [out] err - will fill with error if something go wrong
 *  \result true on succes. false otherwise and err will filled with error
 */
[[nodiscard]] bool asconf_on(int file_descr, std::string &err);

/*! \brief connect sctp with peer
 *  \param [in] peer_addr - peer address
 *  \param [in] file_descr  -  self file descriptor
 *  \param [out] err - will fill with error if something go wrong
 *  \result true on succes. false otherwise and err will filled with error
 */
[[nodiscard]] bool connect_sctp_streams(proto::ip::full_address const &peer_addr, int file_descr, std::string &err);

/*! \brief set sctp specific options
 *  \param [in] ver - ip protocol version
 *  \param [in] settings - pointer on sctp settings
 *  \param [in] file_descr - file descriptor
 *  \param [out] err - will fill with error if something go wrong
 *  \result true on succes. false otherwise and err will filled with error
 */
bool set_sctp_options(proto::ip::address::version ver,
                      bro::net::sctp::settings *settings,
                      int file_descr,
                      std::string &err);
#endif // WITH_SCTP

} // namespace bro::net
