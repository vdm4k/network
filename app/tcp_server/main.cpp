#include <protocols/ip/full_address.h>
#include <socket_proxy/linux/stream_factory.h>
#include <socket_proxy/linux/tcp_settings.h>

#include <atomic>
#include <iostream>
#include <thread>

#include "CLI/CLI.hpp"

bool print_debug_info = false;
size_t data_size = 65000;

struct common_data {
  std::vector<jkl::stream_ptr> _streams;
  std::set<jkl::stream *> _need_to_handle;
  size_t _count = 0;
  jkl::sp::lnx::ev_stream_factory *_manager;
};

void received_data_cb(jkl::stream *stream, std::any data_com) {
  std::byte data[data_size];
  common_data *cdata = std::any_cast<common_data *>(data_com);
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

void state_changed_cb(jkl::stream *stream, std::any data_com) {
  if (print_debug_info)
    std::cout << "state_changed_cb " << stream->get_state() << std::endl;
  if (!stream->is_active()) {
    common_data *cdata = std::any_cast<common_data *>(data_com);
    cdata->_need_to_handle.insert(stream);
  }
}

auto in_socket_fun =
    [](jkl::stream_ptr &&stream,
       jkl::sp::lnx::listen_stream_socket_parameters::in_conn_handler_data_cb
           data) {
      if (!stream->is_active()) {
        std::cerr << "fail to create incomming connection "
                  << stream->get_detailed_error() << std::endl;
        return;
      }
      if (print_debug_info) {
        auto *linux_stream =
            dynamic_cast<jkl::sp::lnx::send_stream_socket_parameters const *>(
                stream->get_stream_settings());
        std::cout << "incoming connection from - " << *linux_stream->_self_addr
                  << ", to - " << linux_stream->_peer_addr << std::endl;
      }

      auto *cdata = std::any_cast<common_data *>(data);
      stream->set_received_data_cb(received_data_cb, data);
      stream->set_state_changed_cb(state_changed_cb, data);
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
  if (!listen_stream->is_active()) {
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
         listen_stream->is_active()) {
    manager.proceed();
    if (!cdata._need_to_handle.empty()) {
      auto &to_handle = cdata._need_to_handle;
      while (!to_handle.empty()) {
        auto beg = to_handle.begin();
        for (auto it = cdata._streams.begin();
             !(*beg)->is_active() && it != cdata._streams.end(); ++it) {
          if (it->get() == *beg) {
            cdata._streams.erase(it);
            break;
          }
        }
        to_handle.erase(beg);
      }
    }
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
