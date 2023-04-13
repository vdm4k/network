#pragma once
#include <openssl/types.h>
#include <string>

namespace bro::net::ssl {

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

/*!
 * \brief Set cipher list for context
 * \param [in] ctx The SSL context to check the certificate and key paths for.
 * \param [in] ciphers all ciphers
 * \param [out] err - will fill with error if something go wrong
 * \return  true on succes. false otherwise and err will filled with error
 */
[[nodiscard]] bool set_cipher_list(SSL_CTX *ctx, std::string const &ciphers, std::string &err);

/*! \brief This function init openSSL library. (safe to call simultaniously from different threads)
 *  \return  true on succes. false otherwise and err will filled with error
 *
 *  \note using spin locks to prevent race conditions
 */
[[nodiscard]] bool init_openSSL();

/*! \brief This function creates a string containing an error message from err and openSSL ( if set )
 * \param [in] err A pointer to a null-terminated string containing the error message.
 * \param [in] ssl_error_code error code from openSSL
 * \result A string containing the error message
 */
std::string fill_error(char const *const err, int ssl_error_code = 0);

/*! \brief This function creates a string containing an error message from err and openSSL ( if set )
 * \param [in] err A string with error message.
 * \param [in] ssl_error_code error code from openSSL
 * \result A string containing the error message
 */
std::string fill_error(std::string const &err, int ssl_error_code = 0);

/*! \brief get salt generated in init phase
 *  \return pointer on salt and salt size
 *
 *  \note we don't check is openSSL library inited for simplifying
 */
std::pair<unsigned char *, size_t> get_salt();

} // namespace bro::net::ssl
