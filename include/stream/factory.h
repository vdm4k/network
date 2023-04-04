#pragma once
#include "settings.h"
#include "stream.h"

namespace bro::strm {
/** @addtogroup stream
 *  @{
 */

/**
 * \brief stream factory interface
 */
class factory {
public:
  virtual ~factory() {}

  /*! \brief create stream
   *  [in] stream_set pointer on settings
   *
   * \note We always create stream. Even if creaion is failed.
   * If stream created successfully we need to bind stream \ref factory::bind
   * If something went wront we return stream with failed state and
   * \ref stream::get_error_description can be called to get an error
   *
   *  \return stream_ptr created stream
   */
  virtual stream_ptr create_stream(settings *stream_set) = 0;

  /*! \brief bind stream
   *  [in] stream - stream to bind
   *
   * \note We always need to bind created stream to factory. Only after that we start
   * to handle all events for this stream.
   */
  virtual void bind(stream_ptr &stream) = 0;

  /*! \brief proceed event loop
   *
   *  This function is a main funcion to generate/handle in/out events.
   *  Hence we need to call it periodically
   */
  virtual void proceed() = 0;
};

} // namespace bro::strm
