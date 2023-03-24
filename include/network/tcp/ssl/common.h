#pragma once
#include <openssl/types.h>
#include <string>

namespace bro::net::tcp::ssl {

bool check_ceritficate(SSL_CTX *ctx, std::string const &cert_path,
                       std::string const &key_path,
                       std::string &detailed_error);
void init_openSSL();
std::string ssl_error();
} // namespace bro::net::tcp::ssl
