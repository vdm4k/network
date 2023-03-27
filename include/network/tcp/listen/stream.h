#pragma once
#include <network/libev/libev.h>
#include <network/tcp/send/stream.h>
#include <network/tcp/stream.h>

#include "network/common.h"
#include "settings.h"
#include "statistic.h"

namespace bro::net::tcp::listen {

/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief listen stream
 */
class stream : public tcp::stream {
 public:
  ~stream();

  /*!
   *  \brief couldn't send data in listen stream. if call this function
   * stream::get_detailed_error will be set \param [in] ptr pointer on data
   *  \param [in] len data lenght
   *  \return always return 0
   */
  ssize_t send(std::byte * /*data*/, size_t /*data_size*/) override;

  /*!
   *  \brief couldn't receive data in listen stream if call this function
   * stream::get_detailed_error will be set \param [in] ptr pointer on data
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

  /*! \brief set callback on data receive ( don't do anything )
   *  \param [in] cb pointer on callback function if nullptr - non
   * active
   * \param [in] param parameter for callback function
   */
  void set_send_data_cb(strm::send_data_cb cb, std::any param) override;

  /*! \brief get actual stream settings
   *  \return settings
   */
  settings const *get_settings() const override { return &_settings; }

  /*! \brief get actual stream statistic
   *  \return stream_statistic
   */
  statistic const *get_statistic() const override { return &_statistic; }

  /*! \brief reset actual statistic
   */
  void reset_statistic() override;

  /*! \brief check if stream in active state
   *  \return bool
   */
  bool is_active() const override;

  /*! \brief get self address
   *  \return return self address
   */
  proto::ip::full_address const &get_self_address() const;

  /*!
   *  \brief init listen stream
   *  \param [in] listen_params pointer on parameters
   *  \return true if inited. otherwise false (cause in get_detailed_error )
   */
  bool init(settings *listen_params);

  /*!
   *  \brief assign event loop to current stream
   *  \param [in] loop pointer on loop
   */
  void assign_loop(struct ev_loop *loop);

 protected:
  virtual std::unique_ptr<send::stream> generate_send_stream();
  virtual void handle_incoming_connection(
      new_connection_details const &result);

  virtual bool fill_send_stream(const new_connection_details &result,
                                std::unique_ptr<send::stream> &sck);

  void cleanup();

 private:
  friend void incoming_connection_cb(struct ev_loop * /*loop*/, ev_io *w,
                                     int /*revents*/);

  bool create_listen_socket();

  ev_io _connect_io;                ///< wait connection event
  struct ev_loop *_loop = nullptr;  ///< pointer on base event loop
  settings _settings;               ///< current settings
  statistic _statistic;             ///< statistics
};

}  // namespace bro::net::tcp::listen

/** @} */  // end of ev_stream
