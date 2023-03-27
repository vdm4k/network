#pragma once
#include <protocols/ip/full_address.h>

namespace bro::net {

/** @addtogroup network_stream
 *  @{
 */

/*! \brief get ip address for active file descriptor
 * \param [in] ver version of ip protocol
 * \param [in] fd file descriptor
 * \param [out] addr address to fill
 * \result true if success
 */
std::optional<proto::ip::full_address> get_address_from_fd(proto::ip::address::version ver, int fd);

/*! \brief get ip address for active file descriptor
 * \param [in] ver version of ip protocol
 * \param [in] fd file descriptor
 * \param [out] addr address to fill
 * \result true if success
 */
proto::ip::full_address get_address_from_fd(proto::ip::address::version ver, int fd, std::string &detailed_error);

/*! \brief bind current stream on specific address
 *  \param [in] self_address address to bind
 *  \result true if success
 */
[[nodiscard]] bool bind_on_address(proto::ip::full_address &self_address, int file_descr, std::string &detailed_error);

struct new_connection_details {
  proto::ip::full_address _peer_addr;
  proto::ip::full_address _self_address;
  int _client_fd;
};

using accept_connection_res = std::optional<new_connection_details>;

[[nodiscard]] accept_connection_res accept_connection(proto::ip::address::version ip_version, int server_fd);

[[nodiscard]] bool connect_stream(proto::ip::full_address const &peer_addr, int file_descr, std::string &detailed_error);

[[nodiscard]] bool reuse_address(int file_descr, std::string &detailed_error);

[[nodiscard]] bool start_listen(int file_descr, int listen_backlog, std::string &detailed_error);

#ifdef WITH_SCTP
[[nodiscard]] bool bind_on_sctp_address(proto::ip::full_address &self_address,
                                        int file_descr,
                                        std::string &detailed_error);
[[nodiscard]] bool asconf_on(int file_descr, std::string &detailed_error);

[[nodiscard]] bool connect_sctp_streams(proto::ip::full_address const &peer_addr,
                                        int file_descr,
                                        std::string &detailed_error);

#endif

} // namespace bro::net

/** @} */ // end of network_stream
