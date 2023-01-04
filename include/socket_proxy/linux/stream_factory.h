#pragma once
#include <socket_proxy/libev/libev.h>
#include <socket_proxy/stream_factory.h>

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx {

class ev_stream_factory : public jkl::stream_factory {
 public:
  ev_stream_factory() noexcept;
  ev_stream_factory(ev_stream_factory const &) = delete;
  ev_stream_factory(ev_stream_factory &&) = delete;
  ev_stream_factory &operator=(ev_stream_factory &&) = delete;
  ev_stream_factory &operator=(ev_stream_factory const &) = delete;
  ~ev_stream_factory();

  /*! \brief create send/listen stream socket
   *
   * Always create stream. If something bad happens return stream with failed
   * state stream::get_detailed_error can be used to look extended error.
   * stream::get_stream_settings will always return valid settings, hence we can
   * recreate failed stream with settings from failed stream
   *
   * \return stream_ptr created stream
   */
  virtual stream_ptr create_stream(stream_settings *stream_set) override;

  /*! \brief proceed event loop.
   */
  virtual void proceed() override;

 private:
  struct ev_loop *_ev_loop = nullptr;
};

}  // namespace jkl::sp::lnx

/** @} */  // end of stream
