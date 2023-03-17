#pragma once
#include <socket_proxy/libev/libev.h>
#include <socket_proxy/linux/ssl/send/stream.h>
#include <socket_proxy/linux/tcp/listen/stream.h>

#include "settings.h"
#include "statistic.h"

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace bro::sp::tcp::ssl::listen {

/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief listen stream
 */
class stream : public tcp::listen::stream {
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

  ~stream() override;

  /*! \brief get actual stream settings
   *  \return stream_settings
   */
  stream_settings const *get_settings() const override { return &_settings; }

  /*! \brief get actual stream statistic
   *  \return stream_statistic
   */
  stream_statistic const *get_statistic() const override { return &_statistic; }

  /*!
   *  \brief init listen stream
   *  \param [in] listen_params pointer on parameters
   *  \return true if inited. otherwise false (cause in get_detailed_error )
   */
  bool init(settings *listen_params);

 protected:
  std::unique_ptr<bro::sp::tcp::send::stream> generate_send_stream() override;

  bool fill_send_stream(
      int file_descr, bro::proto::ip::full_address const &peer_addr,
      proto::ip::full_address const &self_addr,
      std::unique_ptr<bro::sp::tcp::send::stream> &sck) override;

  void cleanup();

 private:
  settings _settings;
  statistic _statistic;

  SSL_CTX *_ctx = nullptr;
};

}  // namespace bro::sp::tcp::ssl::listen

/** @} */  // end of ev_stream
