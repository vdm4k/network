#pragma once
#include <socket_proxy/libev/libev.h>
#include <socket_proxy/linux/tcp/stream.h>

#include "settings.h"
#include "statistic.h"

namespace jkl::sp::lnx::tcp::listen {

/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief listen stream
 */
class stream : public jkl::sp::lnx::tcp::stream {
 public:
  /**
   * \brief default constructor
   */
  stream() = default;

  /**
   * \brief disabled copy ctor
   *
   * We can't copy and handle event loop
   */
  stream(stream const &) = delete;

  /**
   * \brief disabled move ctor
   *
   * Can be too complex
   */
  stream(stream &&) = delete;

  /**
   * \brief disabled move assign operator
   *
   * Can be too complex
   */
  stream &operator=(stream &&) = delete;

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
  void set_received_data_cb(received_data_cb cb, std::any param) override;

  /*! \brief set callback on data receive ( don't do anything )
   *  \param [in] cb pointer on callback function if nullptr - non
   * active
   * \param [in] param parameter for callback function
   */
  void set_send_data_cb(send_data_cb cb, std::any param) override;

  /*! \brief get actual stream settings
   *  \return stream_settings
   */
  stream_settings const *get_settings() const override { return &_settings; }

  /*! \brief get actual stream statistic
   *  \return stream_statistic
   */
  stream_statistic const *get_statistic() const override { return &_statistic; }

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
  jkl::proto::ip::full_address const &get_self_address() const;

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

 private:
  friend void incoming_connection_cb(struct ev_loop * /*loop*/, ev_io *w,
                                     int /*revents*/);
  void handle_incoming_connection(int file_descr,
                                  proto::ip::full_address const &peer_addr,
                                  proto::ip::full_address const &self_addr);
  bool create_listen_socket();
  void stop_events();

  ev_io _connect_io;
  struct ev_loop *_loop = nullptr;
  settings _settings;
  statistic _statistic;
};

}  // namespace jkl::sp::lnx::tcp::listen

/** @} */  // end of ev_stream
