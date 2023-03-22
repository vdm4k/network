#pragma once
#include <network/sctp/send/statistic.h>
#include <stdint.h>

namespace bro::net::sctp::ssl::send {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief statistic for send stream
 */
struct statistic : public sctp::send::statistic {};
} // namespace bro::net::sctp::ssl::send

/** @} */ // end of ev_stream
