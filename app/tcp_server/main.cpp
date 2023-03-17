#include <protocols/ip/full_address.h>
#include <socket_proxy/linux/stream_factory.h>
#include <socket_proxy/linux/tcp/listen/settings.h>
#include <socket_proxy/linux/tcp/listen/statistic.h>
#include <socket_proxy/linux/tcp/send/settings.h>

#include <atomic>
#include <iostream>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#include "CLI/CLI.hpp"

bool print_debug_info = false;
size_t data_size = 65000;

struct data_per_thread {
  std::unordered_set<bro::stream *> _need_to_handle;
  std::unordered_map<bro::stream *, bro::stream_ptr> _streams;
  size_t _count = 0;
  bro::sp::ev_stream_factory *_manager;
};

void received_data_cb(bro::stream *stream, std::any data_com) {
  std::byte data[data_size];
  data_per_thread *cdata = std::any_cast<data_per_thread *>(data_com);
  cdata->_count++;
  ssize_t size = stream->receive(data, data_size);
  if (size > 0) {
    if (print_debug_info)
      std::cout << "receive message - " << std::string((char *)data, size)
                << std::endl;
  } else {
    if (print_debug_info)
      std::cout << "error message - " << stream->get_detailed_error()
                << std::endl;
    cdata->_need_to_handle.insert(stream);
    return;
  }
  ssize_t const sent = stream->send(data, size);
  if (sent <= 0) {
    if (print_debug_info)
      std::cout << "send error - " << stream->get_detailed_error() << std::endl;
    cdata->_need_to_handle.insert(stream);
  }
}

void state_changed_cb(bro::stream *stream, std::any data_com) {
  if (print_debug_info)
    std::cout << "state_changed_cb " << stream->get_state() << std::endl;
  if (!stream->is_active()) {
    data_per_thread *cdata = std::any_cast<data_per_thread *>(data_com);
    cdata->_need_to_handle.insert(stream);
  }
}

auto in_socket_fun =
    [](bro::stream_ptr &&stream,
       bro::sp::tcp::listen::settings::in_conn_handler_data_cb data) {
      if (!stream->is_active()) {
        std::cerr << "fail to create incomming connection "
                  << stream->get_detailed_error() << std::endl;
        return;
      }
      auto *linux_stream =
          dynamic_cast<bro::sp::tcp::send::settings const *>(
              stream->get_settings());
      std::cout << "incoming connection from - " << linux_stream->_peer_addr
                << ", to - " << *linux_stream->_self_addr << std::endl;

      auto *cdata = std::any_cast<data_per_thread *>(data);
      stream->set_received_data_cb(received_data_cb, data);
      stream->set_state_changed_cb(state_changed_cb, data);
      cdata->_manager->bind(stream);
      cdata->_streams[stream.get()] = std::move(stream);
    };

int main(int argc, char **argv) {
  CLI::App app{"tcp_server"};
  std::string server_address_s;
  uint16_t server_port;
  size_t test_time = 1;  // in seconds

  app.add_option("-a,--address", server_address_s, "server address")
      ->required();
  app.add_option("-p,--port", server_port, "server port")->required();
  app.add_option("-l,--log", print_debug_info, "print debug info");
  app.add_option("-d,--data", data_size, "send data size")
      ->type_size(1, std::numeric_limits<std::uint16_t>::max());
  app.add_option("-t,--test_time", test_time, "test time in seconds");
  CLI11_PARSE(app, argc, argv);

  bro::proto::ip::address server_address(server_address_s);
  if (server_address.get_version() ==
      bro::proto::ip::address::version::e_none) {
    std::cerr << "incorrect address - " << server_address << std::endl;
    return -1;
  }

  bro::sp::ev_stream_factory manager;
  bro::sp::tcp::listen::settings settings;
  std::atomic_bool work(true);

  data_per_thread cdata;
  cdata._manager = &manager;
  settings._listen_address = {server_address, server_port};
  settings._proc_in_conn = in_socket_fun;
  settings._in_conn_handler_data = &cdata;
  auto listen_stream = manager.create_stream(&settings);
  if (!listen_stream->is_active()) {
    std::cerr << "couldn't create listen stream, cause - "
              << listen_stream->get_detailed_error() << std::endl;
    return -1;
  }
  manager.bind(listen_stream);

  auto endTime =
      std::chrono::system_clock::now() + std::chrono::seconds(test_time);

  bro::sp::tcp::listen::statistic stat;
  size_t message_proceed = 0;
  std::cout << "server start" << std::endl;

  while (std::chrono::system_clock::now() < endTime &&
         listen_stream->is_active()) {
    manager.proceed();
    if (!cdata._need_to_handle.empty()) {
      auto it = cdata._need_to_handle.begin();
      if (!(*it)->is_active()) {
        cdata._streams.erase((*it));
        cdata._need_to_handle.erase(it);
      }
    }
    if (cdata._count) {
      message_proceed += cdata._count;
      cdata._count = 0;
    } else {
      std::this_thread::sleep_for(std::chrono::microseconds(10));
    }
  }

  auto const *stream_stat =
      static_cast<bro::sp::tcp::listen::statistic const *>(
          listen_stream->get_statistic());
  stat._failed_to_accept_connections +=
      stream_stat->_failed_to_accept_connections;
  stat._success_accept_connections += stream_stat->_success_accept_connections;

  work = false;
  std::cout << "server stoped" << std::endl;
  std::cout << "message proceed - " << message_proceed << std::endl;
  std::cout << "success accept connections - "
            << stat._success_accept_connections << std::endl;
  std::cout << "failed to accept connections - "
            << stat._failed_to_accept_connections << std::endl;
}
