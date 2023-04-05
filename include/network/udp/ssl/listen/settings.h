#pragma once
#include <network/stream/listen/settings.h>
#include <chrono>

namespace bro::net::udp::ssl::listen {
/** @addtogroup udp_stream_stream
 *  @{
 */

/*! \brief sctp receive connections settings
 */
struct settings : net::listen::settings {
  std::string _certificate_path;                             ///< path to certificate file
  std::string _key_path;                                     ///< path to key file
  bool _enable_sslv2 = true;                                 ///< enable sslv2
  bool _enable_empty_fragments = false;                      ///< enable emplty fragments
  bool _need_auth = false;                                   ///< need authorization for incomming streams
  std::optional<std::chrono::milliseconds> _recieve_timeout; ///< receive timeout
};

} // namespace bro::net::udp::ssl::listen
