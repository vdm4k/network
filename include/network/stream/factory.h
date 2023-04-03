#pragma once
#include <stream/factory.h>
struct ev_loop;

namespace bro::net::ev {
/** @defgroup network_stream
 *  @{
 */

/**
 * \brief stream factory (based on libev)
 */
class factory : public strm::factory {
public:
  /**
   * default constructor
   */
  factory() noexcept;

  /**
   * \brief disabled copy ctor
   *
   * We can't copy and handle event loop
   */
  factory(factory const &) = delete;

  /**
   * \brief disabled move ctor
   *
   * Can be dangerous. Need to remeber all binded streams.
   * (If we override existing loop with already binded streams)
   */
  factory(factory &&) = delete;

  /**
   * \brief disabled move assign operator
   *
   * Can be dangerous. Need to remeber all binded streams.
   * (If we override existing loop with already binded streams)
   */
  factory &operator=(factory &&) = delete;

  /**
   * \brief disabled assign operator
   *
   * We can't copy and handle event loop
   */
  factory &operator=(factory const &) = delete;
  ~factory();

  /*! \brief create stream
   *  [in] stream_set pointer on settings
   *
   * Always create stream.
   * If success created stream we need to bind stream to factory
   * bind(stream_ptr& stream).
   * If something went wront we return stream with
   * failed state and stream::get_detailed_error this can be used to look
   * an extended error.
   *
   *  \return stream_ptr created stream
   */
  strm::stream_ptr create_stream(strm::settings *stream_set) override;

  /*! \brief bind stream
   *  [in] stream
   *
   * We always need to bind created stream to factory. Only after that we start
   * to handle all events
   */
  void bind(strm::stream_ptr &stream) override;

  /*! \brief proceed event loop
   *
   *  This function is a main funcion to generate/handle in/out events.
   *  Hence we need to call it periodically
   */
  void proceed() override;

private:
  struct ev_loop *_ev_loop = nullptr;
};

} // namespace bro::net::ev

/** @} */ // end of network_stream
