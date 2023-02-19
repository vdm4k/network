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

  /*! \brief create stream (Always create stream)
   *
   * Success created stream need to bind to any factory
   * If something bad happened we return stream with failed
   * state - stream::get_detailed_error this can be used for look extended
   * error. stream::get_stream_settings will always return valid settings, hence
   * we can recreate failed stream with settings from failed stream
   *
   *  \return stream_ptr created stream
   */
  virtual stream_ptr create_stream(stream_settings* stream_set) = 0;

  /*! \brief bind stream to specific factory
   *
   *  We always need to bind created stream to factory
   */
  virtual void bind(stream_ptr& stream) = 0;

  /*! \brief proceed event loop
   *
   *  Need to bind stream to factory before we can handle it
   */
  virtual void proceed() = 0;
};

}  // namespace jkl

/** @} */  // end of stream
