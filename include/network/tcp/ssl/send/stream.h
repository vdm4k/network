#pragma once
#include <network/tcp/send/stream.h>
#include <openssl/types.h>
#include "settings.h"
#include "statistic.h"

namespace bro::net::tcp::ssl::listen {
class stream;
} // namespace bro::net::tcp::ssl::listen

namespace bro::net::tcp::ssl::send {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief send stream
 */
class stream : public tcp::send::stream {
public:
  ~stream() override;

  /*! \brief receive data
   *  \param [in] data pointer on buffer
   *  \param [in] data_size buffer lenght
   *  \return ssize_t if ssize_t is positive - received data size otherwise
   * ssize_t interpet as error
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
   *  \return true if inited. otherwise false (cause in get_detailed_error )
   */
  bool init(settings *send_params);

protected:
  void cleanup();
  [[nodiscard]] bool connection_established() override;
  ssize_t send_data(std::byte const *data, size_t data_size, bool resend = false) override;

private:
  friend class ssl::listen::stream;

  SSL *_ctx = nullptr;
  SSL_CTX *_client_ctx = nullptr;
  settings _settings;   ///< current settings
  statistic _statistic; ///< statistics
};

} // namespace bro::net::tcp::ssl::send

/** @} */ // end of ev_stream
