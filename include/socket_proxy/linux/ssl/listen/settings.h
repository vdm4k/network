#pragma once
#include <protocols/ip/full_address.h>
#include <socket_proxy/linux/tcp/listen/settings.h>
#include <socket_proxy/stream.h>

#include <any>
#include <functional>

namespace bro::sp::tcp::ssl::listen {
/** @addtogroup ev_stream
 *  @{
 */

/*! \brief tcp receive connections settings
 */
struct settings : bro::sp::tcp::listen::settings {
  std::string _certificate_path;
  std::string _key_path;
  bool _enable_sslv2 = true;
  bool _enable_empty_fragments = false;
  bool _enable_http2 = false;
};

}  // namespace bro::sp::tcp::ssl::listen

/** @} */  // end of ev_stream
