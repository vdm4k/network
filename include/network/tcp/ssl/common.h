#pragma once
#include <string>

namespace bro::net::tcp::ssl {
void init_openSSL();
std::string ssl_error();
}  // namespace bro::net::tcp::ssl
