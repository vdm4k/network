#pragma once
#include <network/stream/listen/stream.h>
#include "settings.h"

namespace bro::net::sctp::listen {

/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief listen stream
 */
class stream : public net::listen::stream {
public:
  ~stream();

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
   *  \return true if inited. otherwise false (cause in get_detailed_error )
   */
  bool init(settings *listen_params);

protected:
  std::unique_ptr<strm::stream> generate_send_stream() override;
  [[nodiscard]] bool fill_send_stream(accept_connection_res const &result, std::unique_ptr<strm::stream> &sck) override;

  void cleanup();
  bool create_socket(proto::ip::address::version version, socket_type s_type) override;

private:
  friend void incoming_connection_cb(struct ev_loop * /*loop*/, ev_io *w, int /*revents*/);

  [[nodiscard]] bool create_listen_socket();

  net::sctp::listen::settings _settings; ///< current settings
};

} // namespace bro::net::sctp::listen

/** @} */ // end of ev_stream
