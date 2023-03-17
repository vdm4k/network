#pragma once
#include <string>

namespace bro::sp::tcp::ssl {
void init_openSSL();
std::string ssl_error();
}  // namespace bro::sp::tcp::ssl
