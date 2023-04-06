#pragma once
#include <openssl/types.h>
#include <network/tcp/listen/stream.h>

#include "settings.h"
#include "statistic.h"

namespace bro::net::tcp::ssl::listen {

/** @addtogroup tcp_ssl_stream
 *  @{
 */

/**
 * \brief listen stream
 */
class stream : public tcp::listen::stream {
public:
  ~stream() override;

  /*! \brief get actual stream settings
   *  \return settings
   */
  settings const *get_settings() const override { return &_settings; }

  /*! \brief get actual stream statistic
   *  \return stream_statistic
   */
  statistic const *get_statistic() const override { return &_statistic; }

  /*!
   *  \brief init listen stream
   *  \param [in] listen_params pointer on parameters
   *  \return true if inited. otherwise false (cause in get_error_description )
   */
  bool init(settings *listen_params);

protected:
  /*! \brief generate send tcp ssl stream
   *  \return generated send stream
   */
  std::unique_ptr<net::stream> generate_send_stream() override;

  /*! \brief fill/set send stream with specific parameters
   */
  [[nodiscard]] bool fill_send_stream(accept_connection_res const &result, std::unique_ptr<net::stream> &sck) override;

  /*! \brief cleanup/free resources
   */
  void cleanup() override;

private:
  settings _settings;      ///< current settings
  statistic _statistic;    ///< statistics
  SSL_CTX *_ctx = nullptr; ///< pointer on ssl context
};

} // namespace bro::net::tcp::ssl::listen
