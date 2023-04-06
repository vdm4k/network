#pragma once
#include <network/stream/send/stream.h>
#include "settings.h"
#include "statistic.h"

namespace bro::net::sctp::send {
/** @addtogroup sctp_stream
 *  @{
 */

/**
 * \brief send stream
 */
class stream : public bro::net::send::stream {
public:
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
  strm::statistic const *get_statistic() const override { return &_statistic; }

  /*! \brief reset actual statistic
   */
  void reset_statistic() override;

  /*!
   *  \brief init send stream
   *  \param [in] send_params pointer on parameters
   *  \return true if inited. otherwise false (cause in get_error_description )
   */
  bool init(settings *send_params);

protected:
  /*! \brief connect stream
   *  \return true if inited. otherwise false (cause in get_error_description )
   */
  [[nodiscard]] bool connect();

  /*! \brief create new sctp send socket
   */
  bool create_socket(proto::ip::address::version version, socket_type s_type) override;

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
  /*! \brief parse sctp notification and handle if needed
   */
  bool is_notification_ok(std::byte *buffer);

  settings _settings;               ///< current settings
  sctp::send::statistic _statistic; ///< statistics
};

} // namespace bro::net::sctp::send
