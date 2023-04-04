#pragma once
#include <openssl/types.h>
#include <string>

namespace bro::net::tcp::ssl {

/** @defgroup tcp_ssl_stream tcp_ssl_stream
 *  @{
 */

/*!
 * \brief Set check sertificate
 * \param [in] ctx The SSL context to check the certificate and key paths for.
 * \param [in] cert_path The file path of the certificate to check.
 * \param [in] key_path The file path of the key to check.
 * \param [out] err - will fill with error if something go wrong
 * \return  true on succes. false otherwise and err will filled with error
 */
[[nodiscard]] bool set_check_ceritficate(SSL_CTX *ctx,
                                         std::string const &cert_path,
                                         std::string const &key_path,
                                         std::string &err);

/*! \brief This function init openSSL library. (safe to call simultaniously from different threads)
 *  \return  true on succes. false otherwise and err will filled with error
 *
 *  \note using spin locks to prevent race conditions
 */
[[nodiscard]] bool init_openSSL();

/*! \brief This function genereate string representation from openssl library
 *  \return filled string if error exist. empty string otherwise
 */
std::string ssl_error();

/*! \brief This function disable sigpipe generation for whole process
 *  \return  true on succes. false otherwise and err will filled with error
 *
 *  \note better to call before start other threads ( from main thread )
 */
bool disable_sig_pipe();

/*! \brief get salt generated in init phase
 *  \return pointer on salt and salt size
 *
 *  \note we don't check is openSSL library inited for simplifying
 */
std::pair<unsigned char *, size_t> get_salt();

} // namespace bro::net::tcp::ssl
