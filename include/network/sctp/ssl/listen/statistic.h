#pragma once
#include <network/sctp/listen/statistic.h>

namespace bro::net::sctp::ssl::listen {
/** @addtogroup sctp_ssl_stream
 *  @{
 */

/**
 * \brief statistic for listen stream
 */
struct statistic : public sctp::listen::statistic {};
} // namespace bro::net::sctp::ssl::listen
