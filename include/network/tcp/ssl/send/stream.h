#pragma once
#include <network/tcp/send/stream.h>
#include <openssl/types.h>
#include "settings.h"
#include "statistic.h"

namespace bro::net::tcp::ssl::listen {
class stream;
} // namespace bro::net::tcp::ssl::listen

namespace bro::net::tcp::ssl::send {
/** @addtogroup tcp_ssl_stream
 *  @{
 */

/**
 * \brief send stream
 */
class stream : public tcp::send::stream {
public:
  ~stream() override;

  /*! \brief This function receive data
   *  \param [in] data pointer on a buffer
   *  \param [in] data_size buffer lenght
   *  \return ssize_t 3 options
   *  1. Positive - The number of bytes sent
   *  2. Negative - an error occurred
   *  3. Zero - only if pass zero data_size
   */
  ssize_t receive(std::byte *data, size_t data_size) override;

  /*! \brief get actual stream settings
   *  \return settings
   */
  settings const *get_settings() const override { return &_settings; }

  /*! \brief get actual stream statistic
   *  \return stream_statistic
   */
  statistic const *get_statistic() const override { return &_statistic; }

  /*!
   *  \brief init send stream
   *  \param [in] send_params pointer on parameters
   *  \return true if inited. otherwise false (cause in get_error_description )
   */
  bool init(settings *send_params);

protected:
  /*! \brief cleanup/free resources
   */
  void cleanup() override;

  /*! \brief if connection established succesfully will prepare connection for receiving events
   *  \return true if init complete successful
   */
  [[nodiscard]] bool connection_established() override;

  /*! \brief send data using underlying protocol
   *  \param [in] data pointer on a data to send
   *  \param [in] data_size data lenght
   *  \return ssize_t 3 options
   *  1. Positive - The number of bytes sent
   *  2. Negative - an error occurred
   *  3. Zero - only if pass zero data_size
   */
  ssize_t send_data(std::byte const *data, size_t data_size) override;

private:
  friend class ssl::listen::stream;

  SSL *_ctx = nullptr;            ///< pointer on ssl session
  SSL_CTX *_client_ctx = nullptr; ///< pointer on ssl context
  settings _settings;             ///< current settings
  statistic _statistic;           ///< statistics
};

} // namespace bro::net::tcp::ssl::send
