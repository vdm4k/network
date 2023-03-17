#pragma once
#include <protocols/ip/full_address.h>
#include <socket_proxy/linux/tcp/send/settings.h>

#include <optional>

namespace bro::sp::tcp::ssl::send {
/** @addtogroup ev_stream
 *  @{
 */

/*!\brief tcp send stream settings
 */
struct settings : bro::sp::tcp::send::settings {
  bool _enable_sslv2 = true;
  bool _enable_empty_fragments = false;
  bool _enable_http2 = false;
};

}  // namespace bro::sp::tcp::ssl::send

/** @} */  // end of ev_stream
