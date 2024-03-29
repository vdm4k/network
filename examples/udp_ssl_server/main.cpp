#include <network/udp/ssl/listen/settings.h>
#include <network/udp/ssl/listen/statistic.h>
#include <network/udp/ssl/send/settings.h>
#include <network/udp/ssl/send/statistic.h>
#include <network/stream/factory.h>
#include <network/platforms/system.h>

#include <atomic>
#include <iostream>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "CLI/CLI.hpp"

using namespace bro::net;
using namespace bro::strm;

bool print_debug_info = false;
size_t data_size = 65000;

using namespace bro::net;
using namespace bro::strm;

struct data_per_thread {
  std::unordered_set<stream *> _need_to_handle;
  std::unordered_map<stream *, stream_ptr> _streams;
  size_t _count = 0;
  ev::factory *_manager;
};

void received_data_cb(stream *stream, std::any data_com) {
  std::byte data[data_size];
  data_per_thread *cdata = std::any_cast<data_per_thread *>(data_com);
  cdata->_count++;
  ssize_t size = stream->receive(data, data_size);
  if (size > 0) {
    if (print_debug_info)
      std::cout << "receive message - " << std::string((char *) data, size) << std::endl;
    ssize_t const sent = stream->send(data, size);
    if (sent <= 0) {
      if (print_debug_info)
        std::cout << "send error - " << stream->get_error_description() << std::endl;
      cdata->_need_to_handle.insert(stream);
    }
  } else {
    if (print_debug_info)
      std::cout << "error message - " << stream->get_error_description() << std::endl;
    cdata->_need_to_handle.insert(stream);
    return;
  }
}

void state_changed_cb(stream *stream, std::any data_com) {
  if (!stream->is_active()) {
    std::cout << "state_changed_cb " << stream->get_state() << ", " << stream->get_error_description() << std::endl;
    data_per_thread *cdata = std::any_cast<data_per_thread *>(data_com);
    cdata->_need_to_handle.insert(stream);
  } else
    std::cout << "state_changed_cb " << stream->get_state() << std::endl;
}

auto in_connections = [](stream_ptr &&stream, udp::ssl::listen::settings::in_conn_handler_data_cb data) {
  if (!stream->is_active()) {
    std::cerr << "fail to create incomming connection " << stream->get_error_description() << std::endl;
    return;
  }
  auto *linux_stream = dynamic_cast<udp::send::settings const *>(stream->get_settings());
  std::cout << "incoming connection from - " << linux_stream->_peer_addr << ", to - " << *linux_stream->_self_addr
            << std::endl;

  auto *cdata = std::any_cast<data_per_thread *>(data);
  stream->set_received_data_cb(::received_data_cb, data);
  stream->set_state_changed_cb(::state_changed_cb, data);
  cdata->_manager->bind(stream);
  cdata->_streams[stream.get()] = std::move(stream);
};

int main(int argc, char **argv) {
  CLI::App app{"udp_ssl_server"};
  std::string server_address_s;
  uint16_t server_port;
  size_t test_time = 1; // in seconds
  std::string certificate_path{"certificate.pem"};
  std::string key_path{"key.pem"};

  app.add_option("-a,--address", server_address_s, "server address")->required();
  app.add_option("-p,--port", server_port, "server port")->required();
  app.add_option("-l,--log", print_debug_info, "print debug info");
  app.add_option("-d,--data", data_size, "send data size")->type_size(1, std::numeric_limits<std::uint16_t>::max());
  app.add_option("-t,--test_time", test_time, "test time in seconds");
  app.add_option("-c,--certificate_path", certificate_path, "certificate path");
  app.add_option("-k,--key_path", key_path, "key path");
  CLI11_PARSE(app, argc, argv);

  disable_sig_pipe();

  proto::ip::address server_address(server_address_s);
  if (server_address.get_version() == proto::ip::address::version::e_none) {
    std::cerr << "incorrect address - " << server_address << std::endl;
    return -1;
  }

  ev::factory manager;
  udp::ssl::listen::settings settings;
  std::atomic_bool work(true);

  data_per_thread cdata;
  cdata._manager = &manager;
  settings._listen_address = {server_address, server_port};
  settings._proc_in_conn = in_connections;
  settings._in_conn_handler_data = &cdata;
  settings._certificate_path = certificate_path;
  settings._key_path = key_path;
  auto listen_stream = manager.create_stream(&settings);
  if (!listen_stream->is_active()) {
    std::cerr << "couldn't create listen stream, cause - " << listen_stream->get_error_description() << std::endl;
    return -1;
  }
  manager.bind(listen_stream);

  auto endTime = std::chrono::system_clock::now() + std::chrono::seconds(test_time);

  udp::ssl::listen::statistic stat;
  std::cout << "server start" << std::endl;
  udp::ssl::send::statistic client_stat;

  while (std::chrono::system_clock::now() < endTime && listen_stream->is_active()) {
    manager.proceed();
    if (!cdata._need_to_handle.empty()) {
      auto it = cdata._need_to_handle.begin();
      if (!(*it)->is_active()) {
        client_stat += *static_cast<udp::ssl::send::statistic const *>((*it)->get_statistic());
        cdata._streams.erase((*it));
        cdata._need_to_handle.erase(it);
      }
    }
    if (cdata._count) {
      cdata._count = 0;
    } else {
      std::this_thread::sleep_for(std::chrono::microseconds(10));
    }
  }

  for (auto &strm : cdata._streams) {
    client_stat += *static_cast<udp::ssl::send::statistic const *>(strm.first->get_statistic());
  }

  auto const *stream_stat = static_cast<udp::ssl::listen::statistic const *>(listen_stream->get_statistic());
  stat._failed_to_accept_connections += stream_stat->_failed_to_accept_connections;
  stat._success_accept_connections += stream_stat->_success_accept_connections;

  work = false;
  std::cout << "server stoped" << std::endl;
  std::cout << "success accept connections - " << stat._success_accept_connections << std::endl;
  std::cout << "failed to accept connections - " << stat._failed_to_accept_connections << std::endl;
  std::cout << "success_send_data - " << client_stat._success_send_data << std::endl;
  std::cout << "retry_send_data - " << client_stat._retry_send_data << std::endl;
  std::cout << "failed_send_data - " << client_stat._failed_send_data << std::endl;
  std::cout << "success_recv_data - " << client_stat._success_recv_data << std::endl;
  std::cout << "retry_recv_data - " << client_stat._retry_recv_data << std::endl;
  std::cout << "failed_recv_data - " << client_stat._failed_recv_data << std::endl;
}
