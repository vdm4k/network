#pragma once
#include <network/stream/listen/stream.h>

#include "settings.h"

namespace bro::net::tcp::listen {

/** @defgroup tcp_stream tcp_stream
 *  @{
 */

/**
 * \brief listen stream
 */
class stream : public net::listen::stream {
public:
  /*! \brief get actual stream settings
   *  \return settings
   */
  settings const *get_settings() const override { return &_settings; }

  /*!
   *  \brief init listen stream
   *  \param [in] listen_params pointer on parameters
   *  \return true if inited. otherwise false (cause in get_error_description )
   */
  bool init(settings *listen_params);

protected:
  /*! \brief generate send tcp stream
   *  \return generated send stream
   */
  std::unique_ptr<net::stream> generate_send_stream() override;

  /*! \brief create new tcp listen socket and set sctp parammeters
   */
  bool create_socket(proto::ip::address::version version, socket_type s_type) override;

private:
  /*! \brief create and set settings socket
   */
  [[nodiscard]] bool create_listen_socket();

  settings _settings; ///< current settings
};

} // namespace bro::net::tcp::listen
