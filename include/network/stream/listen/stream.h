#pragma once
#include <network/platforms/libev/libev.h>
#include <network/platforms/system.h>
#include <network/stream/stream.h>

#include "statistic.h"

namespace bro::net::listen {

/** @addtogroup network_stream
 *  @{
 */

/**
 * \brief class needed for work with libev.
 *        also handle processing usual routine for listen socket
 */
class stream : public net::stream {
public:
  ~stream();

  /*! \brief send data
   *  \param [in] data pointer on data
   *  \param [in] data_size data lenght
   *  \return ssize_t if ssize_t is positive - sended data size otherwise
   *  ssize_t interpet as error
   */
  ssize_t send(std::byte const *data, size_t data_size) override;

  /*!
   *  \brief couldn't receive data in listen stream if call this function
   * stream::get_error_description will be set \param [in] ptr pointer on data
   *  \param [in] ptr pointer on buffer
   *  \param [in] len buffer lenght
   *  \return always return 0
   */
  ssize_t receive(std::byte * /*data*/, size_t /*data_size*/) override;

  /*! \brief set callback on data receive ( don't do anything )
   *  \param [in] cb pointer on callback function if nullptr - non
   * active
   * \param [in] param parameter for callback function
   */
  void set_received_data_cb(strm::received_data_cb cb, std::any param) override;

  /*! \brief check if stream in active state
   *  \return bool
   */
  bool is_active() const override;

  /*! \brief get actual stream statistic
   *  \return stream_statistic
   */
  strm::statistic const *get_statistic() const override { return &_statistic; }

  /*! \brief reset actual statistic
   */
  void reset_statistic() override;

  /*! \brief assign event loop to current stream
   *  \param [in] loop pointer on loop
   */
  void assign_loop(struct ev_loop *loop);

protected:
  /*! \brief generate send stream of specific type
   *  \return generated send stream
   */
  virtual std::unique_ptr<strm::stream> generate_send_stream() = 0;

  /*! \brief process new incomming connection
   */
  virtual void handle_incoming_connection(accept_connection_res const &result);

  /*! \brief add to new stream specific parameters
   */
  [[nodiscard]] virtual bool fill_send_stream(accept_connection_res const &result,
                                              std::unique_ptr<strm::stream> &new_stream);

  /*! \brief cleanup/free resources
   */
  void cleanup();

private:
  friend void incoming_connection_cb(struct ev_loop * /*loop*/, ev_io *w, int /*revents*/);

  statistic _statistic;            ///< statistics
  ev_io _connect_io;               ///< wait connection event
  struct ev_loop *_loop = nullptr; ///< pointer on base event loop
};

} // namespace bro::net::listen

/** @} */ // end of network_stream
