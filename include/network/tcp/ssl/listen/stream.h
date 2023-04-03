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
  std::unique_ptr<strm::stream> generate_send_stream() override;

  [[nodiscard]] bool fill_send_stream(accept_connection_res const &result, std::unique_ptr<strm::stream> &sck) override;

  void cleanup();

private:
  settings _settings;
  statistic _statistic;

  SSL_CTX *_ctx = nullptr;
};

} // namespace bro::net::tcp::ssl::listen

/** @} */ // end of tcp_ssl_stream
