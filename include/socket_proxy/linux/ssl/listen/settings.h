#pragma once
#include <protocols/ip/full_address.h>
#include <socket_proxy/linux/tcp/listen/settings.h>
#include <socket_proxy/stream.h>

#include <any>
#include <functional>

namespace jkl::sp::tcp::ssl::listen {
/** @addtogroup ev_stream
 *  @{
 */

/*! \brief tcp receive connections settings
 */
struct settings : jkl::sp::tcp::listen::settings {
  bool _enable_sslv2 = true;
  bool _enable_http2 = false;
};

}  // namespace jkl::sp::tcp::ssl::listen

/** @} */  // end of ev_stream
