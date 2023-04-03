#pragma once
#include <protocols/ip/full_address.h>
#ifdef WITH_SCTP
#include <network/sctp/settings.h>
#endif

namespace bro::net {

/** @addtogroup network_stream
 *  @{
 */

enum class socket_type { e_tcp, e_sctp, e_udp };

std::string fill_error(char const *const error_des);
std::string fill_error(std::string const &error_des);

/*! \brief get ip address for active file descriptor
 * \param [in] ver version of ip protocol
 * \param [in] fd file descriptor
 * \param [out] addr address to fill
 * \result true if success
 */
std::optional<proto::ip::full_address> get_address_from_fd(proto::ip::address::version ver, int file_descr);

/*! \brief get ip address for active file descriptor
 * \param [in] ver version of ip protocol
 * \param [in] fd file descriptor
 * \param [out] addr address to fill
 * \result true if success
 */
proto::ip::full_address get_address_from_fd(proto::ip::address::version ver,
                                            int file_descr,
                                            std::string &detailed_error);

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

[[nodiscard]] std::optional<int> create_socket(proto::ip::address::version proto_ver,
                                               socket_type s_type,
                                               std::string &detailed_error);

bool close_socket(int &file_descr, std::string &detailed_error);

[[nodiscard]] bool set_non_blocking_mode(int file_descr, std::string &detailed_error);

[[nodiscard]] bool set_socket_buffer_size(int file_descr, int buffer_size, std::string &detailed_error);

#ifdef WITH_SCTP
[[nodiscard]] bool bind_on_sctp_address(proto::ip::full_address &self_address,
                                        int file_descr,
                                        std::string &detailed_error);
[[nodiscard]] bool asconf_on(int file_descr, std::string &detailed_error);

[[nodiscard]] bool connect_sctp_streams(proto::ip::full_address const &peer_addr,
                                        int file_descr,
                                        std::string &detailed_error);
bool set_sctp_options(proto::ip::address::version ver,
                      bro::net::sctp::settings *settings,
                      int file_descr,
                      std::string &detailed_error);

#endif
bool set_tcp_options(int file_descr, std::string &detailed_error);

[[nodiscard]] bool is_connection_established(int file_descr, std::string &detailed_error);

} // namespace bro::net

/** @} */ // end of network_stream
