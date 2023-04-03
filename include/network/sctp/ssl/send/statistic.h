#pragma once
#include <network/sctp/send/statistic.h>

namespace bro::net::sctp::ssl::send {
/** @addtogroup sctp_ssl_stream
 *  @{
 */

/**
 * \brief statistic for send stream
 */
struct statistic : public sctp::send::statistic {};
} // namespace bro::net::sctp::ssl::send

/** @} */ // end of sctp_ssl_stream
