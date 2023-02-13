#pragma once
#include <socket_proxy/stream.h>
#include <socket_proxy/stream_settings.h>

/** @addtogroup stream
 *  @{
 */

namespace jkl {

class stream_factory {
 public:
  virtual ~stream_factory() {}

  /*! \brief create stream
   *
   * Always create stream. If something bad happens return stream with failed
   * state - stream::get_detailed_error can be used to look extended error.
   * stream::get_stream_settings will always return valid settings, hence we can
   * recreate failed stream with settings from failed stream
   *
   *  \return stream_ptr created stream
   */
  virtual stream_ptr create_stream(stream_settings* stream_set) = 0;

  /*! \brief proceed event loop.
   */
  virtual void proceed() = 0;
};

}  // namespace jkl

/** @} */  // end of stream
