#pragma once
#include <network/libev/libev.h>
#include <network/sctp/listen/stream.h>
#include <network/sctp/ssl/send/stream.h>

#include "settings.h"
#include "statistic.h"

typedef struct ssl_st SSL;
typedef struct ssl_ctx_st SSL_CTX;

namespace bro::net::sctp::ssl::listen {

/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief listen stream
 */
class stream : public sctp::listen::stream {
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
   *  \return true if inited. otherwise false (cause in get_detailed_error )
   */
  bool init(settings *listen_params);

protected:
  std::unique_ptr<bro::net::sctp::send::stream> generate_send_stream() override;

  bool
  fill_send_stream(const accept_connection_result &result,
                   std::unique_ptr<bro::net::sctp::send::stream> &sck) override;

  void cleanup();

private:
  settings _settings;
  statistic _statistic;

  SSL_CTX *_ctx = nullptr;
};

} // namespace bro::net::sctp::ssl::listen

/** @} */ // end of ev_stream
