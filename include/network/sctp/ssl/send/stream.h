#pragma once
#include "settings.h"
#include "statistic.h"
#include <network/sctp/send/stream.h>
#include <openssl/bio.h>
#include <openssl/ssl.h>

namespace bro::net::sctp::ssl::listen {
class stream;
} // namespace bro::net::sctp::ssl::listen

namespace bro::net::sctp::ssl::send {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief send stream
 */
class stream : public sctp::send::stream {
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
  /*! \brief send data
   *  \param [in] data pointer on data
   *  \param [in] data_size data lenght
   *  \return ssize_t if ssize_t is positive - sended data size otherwise
   *  ssize_t interpet as error
   */
  ssize_t send_data(std::byte const *data, size_t data_size, bool resend = false) override;

  void cleanup();
  settings *current_settings() override;
  [[nodiscard]] bool connection_established() override;

private:
  friend class ssl::listen::stream;

  SSL *_ctx = nullptr;
  BIO *_bio = nullptr;
  SSL_CTX *_client_ctx = nullptr;
  settings _settings;   ///< current settings
  statistic _statistic; ///< statistics
};

} // namespace bro::net::sctp::ssl::send

/** @} */ // end of ev_stream
