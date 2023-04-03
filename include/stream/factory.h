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
   * [in] stream_set pointer on settings
   *
   * Always create stream.
   * If success created stream we need to bind stream to factory
   * bind(stream_ptr& stream).
   * If something went wront we return stream with
   * failed state and stream::get_error_description this can be used to look
   * an extended error.
   *
   *  \return stream_ptr created stream
   */
  virtual stream_ptr create_stream(settings *stream_set) = 0;

  /*! \brief bind stream
   *  [in] stream
   *
   * We always need to bind created stream to factory. Only after that we start
   * to handle all events
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

/** @} */ // end of stream
