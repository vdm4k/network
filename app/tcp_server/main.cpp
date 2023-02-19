#include <protocols/ip/full_address.h>
#include <socket_proxy/linux/stream_factory.h>
#include <socket_proxy/linux/tcp_settings.h>

#include <atomic>
#include <iostream>
#include <thread>

#include "CLI/CLI.hpp"
#include "socket_proxy/linux/tcp_send_stream.h"

bool print_debug_info = false;
size_t data_size = 65000;

void received_data_cb(jkl::stream *stream, std::any data_received) {
  std::byte data[data_size];
  size_t *count = std::any_cast<size_t *>(data_received);
  (*count)++;
  ssize_t size = stream->receive(data, data_size);
  if (size > 0) {
    if (print_debug_info)
      std::cout << "receive message - " << std::string((char *)data, size)
                << std::endl;
  } else {
    if (print_debug_info)
      std::cout << "error message - " << stream->get_detailed_error()
                << std::endl;
    return;
  }
  ssize_t const sent = stream->send(data, size);
  if (sent <= 0) {
    if (print_debug_info)
      std::cout << "send error - " << stream->get_detailed_error() << std::endl;
  }
}

void state_changed_cb(jkl::stream *stream, std::any) {
  if (print_debug_info)
    std::cout << "state_changed_cb " << stream->get_state() << std::endl;
}

struct common_data {
  std::vector<jkl::stream_ptr> _streams;
  size_t _count = 0;
  jkl::sp::lnx::ev_stream_factory *_manager;
};

auto in_socket_fun =
    [](jkl::stream_ptr &&stream,
       jkl::sp::lnx::listen_stream_socket_parameters::in_conn_handler_data_cb
           data) {
      if (jkl::stream::state::e_closed == stream->get_state() ||
          jkl::stream::state::e_failed == stream->get_state()) {
        std::cerr << "fail to create incomming connection "
                  << stream->get_detailed_error() << std::endl;
        return;
      }
      if (print_debug_info) {
        auto *linux_stream =
            dynamic_cast<jkl::sp::lnx::tcp_send_stream *>(stream.get());
        std::cout << "incoming connection from - "
                  << linux_stream->get_peer_address().to_string() << ", to - "
                  << linux_stream->get_self_address().to_string() << std::endl;
      }

      auto *cdata = std::any_cast<common_data *>(data);
      stream->set_received_data_cb(received_data_cb, &cdata->_count);
      stream->set_state_changed_cb(state_changed_cb, nullptr);
      cdata->_manager->bind(stream);
      cdata->_streams.push_back(std::move(stream));
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

  jkl::proto::ip::address server_address(server_address_s);
  if (server_address.get_version() ==
      jkl::proto::ip::address::version::e_none) {
    std::cerr << "incorrect address - " << server_address << std::endl;
    return -1;
  }

  jkl::sp::lnx::ev_stream_factory manager;
  jkl::sp::lnx::listen_stream_socket_parameters params;
  std::atomic_bool work(true);

  common_data cdata;
  cdata._manager = &manager;
  params._listen_address = {server_address, server_port};
  params._proc_in_conn = in_socket_fun;
  params._in_conn_handler_data = &cdata;
  auto listen_stream = manager.create_stream(&params);
  if (jkl::stream::state::e_closed == listen_stream->get_state() ||
      jkl::stream::state::e_failed == listen_stream->get_state()) {
    std::cerr << "couldn't create listen stream, cause - "
              << listen_stream->get_detailed_error() << std::endl;
    return -1;
  }
  manager.bind(listen_stream);

  auto endTime =
      std::chrono::system_clock::now() + std::chrono::seconds(test_time);

  size_t message_proceed = 0;
  std::cout << "server start" << std::endl;
  while (std::chrono::system_clock::now() < endTime &&
         jkl::stream::state::e_wait == listen_stream->get_state()) {
    manager.proceed();
    if (cdata._count) {
      message_proceed += cdata._count;
      cdata._count = 0;
    } else {
      std::this_thread::sleep_for(std::chrono::microseconds(10));
    }
  }

  work = false;
  std::cout << "server stoped" << std::endl;
  std::cout << "message proceed - " << message_proceed << std::endl;
}
