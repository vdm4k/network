#pragma once
#include <network/udp/send/settings.h>
#include <chrono>

namespace bro::net::udp::ssl::send {
/** @addtogroup udp_stream_stream
 *  @{
 */

/*!\brief sctp send stream settings
 */
struct settings : udp::send::settings {
  std::string _certificate_path;                             ///< path to certificate file
  std::string _key_path;                                     ///< path to key file
  bool _enable_sslv2 = true;                                 ///< enable sslv2
  bool _enable_empty_fragments = false;                      ///< enable emplty fragments
  std::optional<std::chrono::milliseconds> _recieve_timeout; ///< receive timeout
};

} // namespace bro::net::udp::ssl::send
