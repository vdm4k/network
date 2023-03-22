#pragma once
#include <network/sctp/listen/statistic.h>
#include <stdint.h>

namespace bro::net::sctp::ssl::listen {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief statistic for listen stream
 */
struct statistic : public sctp::listen::statistic {};
} // namespace bro::net::sctp::ssl::listen

/** @} */ // end of ev_stream
