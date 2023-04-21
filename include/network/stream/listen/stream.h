#pragma once
#include <libev_wrapper/io.h>
#include <network/platforms/system.h>
#include <network/stream/stream.h>

#include "statistic.h"

namespace bro::net::listen {

/** @addtogroup network_stream
 *  @{
 */

/**
 * \brief listen stream is using only for listen incomming connections
 *  hence no data can be send or receive in this stream.
 */
class stream : public net::stream {
public:
  ~stream();

  /*! \brief do nothing here
   *  \param [in] data pointer on data
   *  \param [in] data_size data lenght
   *  \return -1 (it is wrong to send data in listen stream)
   *
   *  \note error will be set if this call for listen stream
   */
  ssize_t send(std::byte const *data, size_t data_size) override;

  /*! \brief do nothing here
   *  \param [in] data pointer on buffer
   *  \param [in] data_size buffer lenght
   *  \return -1 (it is wrong to receive data from listen stream)
   *
   *  \note error will be set if this call for listen stream
   */
  ssize_t receive(std::byte *data, size_t data_size) override;

  /*! \brief set callback on data receive ( don't do anything here )
   *  \param [in] cb pointer on callback function
   *  \param [in] param parameter for callback function
   */
  void set_received_data_cb(strm::received_data_cb cb, std::any param) override;

  /*! \brief set callback on data send ( don't do anything here )
   *  \param [in] cb callback function.
   *  \param [in] param parameter for callback function
   */
  void set_send_data_cb(strm::received_data_cb cb, std::any param) override;

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
   *  \param [in] in_conn pointer on loop
   */
  void assign_event(bro::ev::io_t &&in_conn);

protected:
  /*! \brief generate send stream of specific type
   *  \return generated send stream
   */
  virtual std::unique_ptr<net::stream> generate_send_stream() = 0;

  /*! \brief process new incomming connection
   */
  virtual void handle_incoming_connection();

  /*! \brief fill/set send stream with specific parameters
   */
  [[nodiscard]] virtual bool fill_send_stream(accept_connection_res const &result,
                                              std::unique_ptr<net::stream> &new_stream);

  /*! \brief cleanup/free resources
   */
  void cleanup() override;

private:
  statistic _statistic;          ///< statistics
  bro::ev::io_t _in_connections; ///< wait connection event
};

} // namespace bro::net::listen
