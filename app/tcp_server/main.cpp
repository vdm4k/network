#include <protocols/ip/full_address.h>
#include <socket_proxy/linux/stream_factory.h>
#include <socket_proxy/linux/tcp_settings.h>

#include <atomic>
#include <iostream>
#include <thread>

#include "CLI/CLI.hpp"
#include "socket_proxy/linux/tcp_send_stream.h"

bool print_debug_info = true;
size_t data_size = 1500;
const size_t max_data_size = 65000;
std::byte send_data[max_data_size];

void received_data_cb(jkl::stream *stream, std::any data_received) {
  bool *flag = std::any_cast<bool *>(data_received);
  std::byte data[data_size];
  ssize_t size = stream->receive(data, data_size);
  *flag = true;
  if (size > 0) {
    if (print_debug_info)
      std::cout << "receive message - " << std::string((char *)data, data_size)
                << std::endl;
  }
}

void state_changed_cb(jkl::stream *stream, std::any) {
  if (print_debug_info)
    std::cout << "state_changed_cb " << stream->get_state() << std::endl;
}

void proceed_function(jkl::stream_ptr &&stream, std::atomic_bool &work) {
  bool data_received = false;
  stream->set_received_data_cb(received_data_cb, &data_received);
  stream->set_state_changed_cb(state_changed_cb, nullptr);
  while (work.load(std::memory_order_acquire) &&
         jkl::stream::state::e_established == stream->get_state()) {
    while (work.load(std::memory_order_acquire) && !data_received)
      std::this_thread::sleep_for(std::chrono::milliseconds(1));

    ssize_t const sent = stream->send(send_data, data_size);
    if (sent <= 0) {
      if (print_debug_info)
        std::cout << "send error - " << stream->get_detailed_error()
                  << std::endl;
    }
  }
}

struct dataForNewConnection {
  std::vector<std::thread> &pool;
  std::atomic_bool &work;
};

void in_socket_fun(
    jkl::stream_ptr &&stream,
    jkl::sp::lnx::listen_stream_socket_parameters::in_conn_handler_data_cb
        data) {
  if (print_debug_info) {
    auto *linux_stream =
        dynamic_cast<jkl::sp::lnx::tcp_send_stream *>(stream.get());
    std::cout << "incoming connection from - "
              << linux_stream->get_peer_address().to_string() << ", to - "
              << linux_stream->get_self_address().to_string() << std::endl;
  }

  auto *storedData = std::any_cast<dataForNewConnection *>(data);
  storedData->pool.push_back(std::thread(proceed_function, std::move(stream),
                                         std::ref(storedData->work)));
}

void fillTestData() {
  memset(send_data, 2, sizeof(send_data));
  char data[] = {'s', 'e', 'r', 'v', 'e', 'r', ' ',
                 'h', 'e', 'l', 'l', 'o', '!'};
  memcpy(send_data, data, sizeof(data));
}

int main(int argc, char **argv) {
  CLI::App app{"tcp_server"};
  std::string server_address_s;
  uint16_t server_port;
  size_t threads_count = 1;
  size_t test_time = 1;  // in seconds

  app.add_option("-a,--address", server_address_s, "server address")
      ->required();
  app.add_option("-p,--port", server_port, "server port")->required();
  app.add_option("-j,--threads", threads_count, "threads count");
  app.add_option("-l,--log", print_debug_info, "print debug info");
  app.add_option("-d,--data", data_size, "send data size")
      ->type_size(1, max_data_size);
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
  std::vector<std::thread> worker_pool;
  dataForNewConnection data{worker_pool, work};
  params._listen_address = {server_address, server_port};
  params._proc_in_conn = in_socket_fun;
  params._in_conn_handler_data = &data;
  auto listen_stream = manager.create_stream(&params);
  if (jkl::stream::state::e_closed == listen_stream->get_state() ||
      jkl::stream::state::e_failed == listen_stream->get_state()) {
    std::cerr << "couldn't create listen stream, cause - "
              << listen_stream->get_detailed_error() << std::endl;
    return -1;
  }
  auto endTime =
      std::chrono::system_clock::now() + std::chrono::seconds(test_time);

  fillTestData();
  std::cout << "server start" << std::endl;
  while (std::chrono::system_clock::now() < endTime &&
         jkl::stream::state::e_wait == listen_stream->get_state()) {
    manager.proceed();
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }

  work = false;
  std::cout << "server stoped" << std::endl;
  for (auto &th : worker_pool) th.join();
}
