#pragma once
#include <stream/factory.h>
struct ev_loop;

namespace bro::net::ev {
/** @addtogroup network_stream
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
   * \note We always create stream. Even if creaion is failed.
   * If stream created successfully we need to bind stream \ref factory::bind
   * If something went wront we return stream with failed state and
   * \ref stream::get_error_description can be called to get an error
   *
   *  \return stream_ptr created stream
   */
  strm::stream_ptr create_stream(strm::settings *stream_set) override;

  /*! \brief bind stream
   *  [in] stream - stream to bind
   *
   * \note We always need to bind created stream to factory. Only after that we start
   * to handle all events for this stream.
   */
  void bind(strm::stream_ptr &stream) override;

  /*! \brief proceed event loop
   *
   *  This function is a main funcion to generate/handle in/out events.
   *  Hence we need to call it periodically
   */
  void proceed() override;

private:
  struct ev_loop *_ev_loop = nullptr; ///< pointer on main loop
};

} // namespace bro::net::ev
