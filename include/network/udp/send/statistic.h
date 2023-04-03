#pragma once
#include <stdint.h>
#include <stream/statistic.h>

//namespace bro::net::udp::send {
///** @addtogroup ev_stream
// *  @{
// */

///**
// * \brief statistic for send stream
// */
//struct statistic : public strm::statistic {
//  uint64_t _success_send_data = 0; ///< success sended data
//  uint64_t _retry_send_data = 0;   ///< retry send
//  uint64_t _failed_send_data = 0;  ///< failed to send
//  uint64_t _success_recv_data = 0; ///< success receive data
//  uint64_t _retry_recv_data = 0;   ///< retry receive
//  uint64_t _failed_recv_data = 0;  ///< failed to receive

//  statistic &operator+=(const statistic &rhs) {
//    _success_send_data += rhs._success_send_data;
//    _retry_send_data += rhs._retry_send_data;
//    _failed_send_data += rhs._failed_send_data;
//    _success_recv_data += rhs._success_recv_data;
//    _retry_recv_data += rhs._retry_recv_data;
//    _failed_recv_data += rhs._failed_recv_data;
//    return *this;
//  }
//};
//} // namespace bro::net::udp::send

///** @} */ // end of ev_stream
