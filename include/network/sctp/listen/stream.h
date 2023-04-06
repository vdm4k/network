#pragma once
#include <network/stream/listen/stream.h>
#include "settings.h"

namespace bro::net::sctp::listen {

/** @addtogroup sctp_stream
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

  /*! \brief get self address
   *  \return return self address
   */
  proto::ip::full_address const &get_self_address() const;

  /*!
   *  \brief init listen stream
   *  \param [in] listen_params pointer on parameters
   *  \return true if inited. otherwise false (cause in get_error_description )
   */
  bool init(settings *listen_params);

protected:
  /*! \brief generate send sctp stream
   *  \return generated send stream
   */
  std::unique_ptr<net::stream> generate_send_stream() override;

  /*! \brief fill/set send stream with specific parameters
   */
  [[nodiscard]] bool fill_send_stream(accept_connection_res const &result, std::unique_ptr<net::stream> &sck) override;

  /*! \brief create new sctp socket and set sctp parammeters
   */
  bool create_socket(proto::ip::address::version version, socket_type s_type) override;

private:
  friend void incoming_connection_cb(struct ev_loop * /*loop*/, ev_io *w, int /*revents*/);

  /*! \brief create listen sctp socket
   *  \return true if init complete successful
   */
  [[nodiscard]] bool create_listen_socket();

  net::sctp::listen::settings _settings; ///< current settings
};

} // namespace bro::net::sctp::listen
