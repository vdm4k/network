#pragma once
#include <socket_proxy/libev/libev.h>
#include <socket_proxy/linux/tcp/stream.h>

#include "settings.h"
#include "statistic.h"

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace jkl::sp::tcp::ssl::listen {

/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief listen stream
 */
class stream : public jkl::sp::tcp::stream {
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

  SSL_CTX *_ctx = nullptr;
};

}  // namespace jkl::sp::tcp::ssl::listen

/** @} */  // end of ev_stream
