#pragma once
#include <netinet/in.h>
#include <protocols/ip/full_address.h>

namespace bro::net {

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
bool fill_sockaddr(proto::ip::full_address &faddr, sockaddr_in &addr,
                   std::string &detailed_error);

/*! \brief bind current stream on specific address
 *  \param [in] self_address address to bind
 *  \result true if success
 */
bool bind_on_address(proto::ip::full_address &self_address, int file_descriptor,
                     std::string &detailed_error);

struct accept_connection_result {
  proto::ip::full_address _peer_addr;
  proto::ip::full_address _self_address;
  std::optional<int> _fd;
};

accept_connection_result accept_new_connection(
    proto::ip::address::version ip_version, int server_fd);

}  // namespace bro::net
