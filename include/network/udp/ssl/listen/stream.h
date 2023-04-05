#pragma once
#include <openssl/types.h>
#include <network/stream/listen/stream.h>
#include "settings.h"
#include "statistic.h"

namespace bro::net::udp::ssl::listen {

/** @defgroup udp_stream_stream udp_stream_stream
 *  @{
 */

/**
 * \brief listen stream
 */
class stream : public net::listen::stream {
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
  /*! \brief generate send sctp ssl stream
   *  \return generated send stream
   */
  std::unique_ptr<strm::stream> generate_send_stream() override;

  /*! \brief fill/set send stream with specific parameters
   */
  [[nodiscard]] bool fill_send_stream(accept_connection_res const &result, std::unique_ptr<strm::stream> &sck) override;

  /*! \brief cleanup/free resources
   */
  void cleanup();

  /*! \brief process new incomming connection
   */
  void handle_incoming_connection() override;

private:
  /*! \brief create listen udp socket
   *  \return true if init complete successful
   */
  bool create_listen_socket();

/*! \brief generate new dtls context for incomming connection
   *  \return true if inited. otherwise false (cause in get_error_description )
   */
  bool generate_new_dtls_context();

  SSL_CTX *_server_ctx = nullptr; ///< pointer on ssl context
  SSL *_dtls_ctx = nullptr;       ///< pointer on inited dtls context. We need this only for init dtls in ssl
  settings _settings;             ///< current settings
  statistic _statistic;           ///< statistics
};

} // namespace bro::net::udp::ssl::listen
