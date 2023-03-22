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
proto::ip::full_address get_local_address(proto::ip::address::version ver,
                                          int fd);

/*! \brief fill sockaddr_in structure from full address
 * \param [in] faddr full address
 * \param [out] addr filled address
 * \return true on success
 */
bool fill_sockaddr(const proto::ip::full_address &faddr, sockaddr_in &addr,
                   std::string &detailed_error);

/*! \brief bind current stream on specific address
 *  \param [in] self_address address to bind
 *  \result true if success
 */
bool bind_on_address(proto::ip::full_address &self_address, int file_descr,
                     std::string &detailed_error);

struct accept_connection_result {
  proto::ip::full_address _peer_addr;
  proto::ip::full_address _self_address;
  std::optional<int> _client_fd;
};

accept_connection_result
accept_new_connection(proto::ip::address::version ip_version, int server_fd);

bool connect_stream(proto::ip::full_address const &peer_addr, int file_descr,
                    std::string &detailed_error);

bool reuse_address(int file_descr, std::string &detailed_error);

bool start_listen(int file_descr, int listen_backlog,
                  std::string &detailed_error);

#ifdef WITH_SCTP
bool bind_on_sctp_address(proto::ip::full_address &self_address, int file_descr,
                          std::string &detailed_error);
bool asconf_on(int file_descr, std::string &detailed_error);

bool connect_sctp_streams(proto::ip::full_address const &peer_addr,
                          int file_descr, std::string &detailed_error);

#endif

} // namespace bro::net

/** @} */ // end of network_stream
