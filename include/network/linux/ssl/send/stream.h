#pragma once
#include <network/linux/tcp/send/stream.h>

#include "settings.h"
#include "statistic.h"

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace bro::net::tcp::ssl::listen {
class stream;
}  // namespace bro::net::tcp::ssl::listen

namespace bro::net::tcp::ssl::send {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief send stream
 */
class stream : public bro::net::tcp::send::stream {
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

  /*! \brief send data
   *  \param [in] data pointer on data
   *  \param [in] data_size data lenght
   *  \return ssize_t if ssize_t is positive - sended data size otherwise
   *  ssize_t interpet as error
   */
  ssize_t send(std::byte *data, size_t data_size) override;

  /*! \brief receive data
   *  \param [in] data pointer on buffer
   *  \param [in] data_size buffer lenght
   *  \return ssize_t if ssize_t is positive - received data size otherwise
   * ssize_t interpet as error
   */
  ssize_t receive(std::byte *data, size_t data_size) override;

  /*! \brief get actual stream settings
   *  \return stream_settings
   */
  stream_settings const *get_settings() const override { return &_settings; }

  /*! \brief get actual stream statistic
   *  \return stream_statistic
   */
  stream_statistic const *get_statistic() const override { return &_statistic; }

  /*!
   *  \brief init send stream
   *  \param [in] send_params pointer on parameters
   *  \return true if inited. otherwise false (cause in get_detailed_error )
   */
  bool init(settings *send_params);

 protected:
  void cleanup();
  settings *current_settings() override;
  void connection_established() override;

 private:
  friend class ssl::listen::stream;

  SSL *_ctx = nullptr;
  SSL_CTX *_client_ctx = nullptr;
  settings _settings;    ///< current settings
  statistic _statistic;  ///< statistics
};

}  // namespace bro::net::tcp::ssl::send

/** @} */  // end of ev_stream
