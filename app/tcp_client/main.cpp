#include <protocols/ip/full_address.h>
#include <socket_proxy/linux/stream_factory.h>
#include <socket_proxy/linux/tcp_settings.h>

#include <atomic>
#include <iostream>
#include <thread>

#include "CLI/CLI.hpp"

bool print_debug_info = false;
size_t data_size = 1500;
const size_t max_data_size = 65000;
std::byte send_data[max_data_size];

void received_data_cb(jkl::stream *stream, std::any data_received) {
  bool *flag = std::any_cast<bool *>(data_received);
  std::byte data[data_size];
  ssize_t size = stream->receive(data, data_size);
  if (size > 0) {
    if (print_debug_info)
      std::cout << "receive message - " << std::string((char *)data, data_size)
                << std::endl;
  }
  *flag = true;
}

void state_changed_cb(jkl::stream *stream, std::any) {
  if (print_debug_info)
    std::cout << "state_changed_cb " << stream->get_state() << std::endl;
}

void send_data_cb(jkl::stream *stream, std::any) {
  if (print_debug_info) std::cout << "data_sended " << std::endl;
}

struct stream_data {
  stream_data(bool received, jkl::stream_ptr &&ptr)
      : data_received(received), stream(std::move(ptr)) {}
  bool data_received;
  jkl::stream_ptr stream;
};

void thread_fun(jkl::proto::ip::address const &server_addr,
                uint16_t server_port, bool print_send_success,
                std::atomic_bool &work, size_t connections_per_thread) {
  jkl::sp::lnx::ev_stream_factory manager;
  jkl::sp::lnx::send_stream_socket_parameters params;
  params._peer_addr = {server_addr, server_port};

  std::vector<std::unique_ptr<stream_data>> stream_pool;

  while (work.load(std::memory_order_acquire)) {
    if (stream_pool.size() < connections_per_thread) {
      auto new_stream = manager.create_stream(&params);
      if (new_stream->is_active()) {
        manager.bind(new_stream);
        auto s_data =
            std::make_unique<stream_data>(true, std::move(new_stream));
        s_data->stream->set_received_data_cb(received_data_cb,
                                             &s_data->data_received);
        s_data->stream->set_state_changed_cb(state_changed_cb, nullptr);
        if (print_send_success)
          s_data->stream->set_send_data_cb(send_data_cb, nullptr);
        stream_pool.push_back(std::move(s_data));
      }
    }

    for (size_t i = 0;
         i < stream_pool.size() && work.load(std::memory_order_acquire); ++i) {
      auto &send_stream = stream_pool[i]->stream;
      if (jkl::stream::state::e_wait == send_stream->get_state() ||
          !stream_pool[i]->data_received)
        continue;
      if (!send_stream->is_active()) {
        std::cerr << "error - " << send_stream->get_detailed_error()
                  << std::endl;
        stream_pool.erase(stream_pool.begin() + i);
        break;
      }

      stream_pool[i]->data_received = false;
      manager.proceed();
      ssize_t const sent = send_stream->send(send_data, data_size);
      if (sent <= 0) {
        if (print_debug_info)
          std::cerr << send_stream->get_detailed_error() << std::endl;
        stream_pool.erase(stream_pool.begin() + i);
        break;
      }
    }
    manager.proceed();
  }
}

void fillTestData() {
  memset(send_data, 1, sizeof(send_data));
  char data[] = {'c', 'l', 'i', 'e', 'n', 't', ' ',
                 'h', 'e', 'l', 'l', 'o', '!'};
  memcpy(send_data, data, sizeof(data));
}

int main(int argc, char **argv) {
  CLI::App app{"tcp_client"};
  std::string server_address_string;
  uint16_t server_port;
  size_t threads_count = 1;
  bool print_send_success = false;
  size_t test_time = 1;  // in seconds
  size_t connections_per_thread = 1;

  app.add_option("-a,--address", server_address_string, "server address")
      ->required();
  app.add_option("-p,--port", server_port, "server port")->required();
  app.add_option("-j,--threads", threads_count, "threads count");
  app.add_option("-l,--log", print_debug_info, "print debug info");
  app.add_option("-d,--data", data_size, "send data size")
      ->type_size(1, max_data_size);
  app.add_option("-w,--send_success", print_send_success, "print send success");
  app.add_option("-t,--test_time", test_time, "test time in seconds");
  app.add_option("-c,--connecions", connections_per_thread,
                 "connections per thread");
  CLI11_PARSE(app, argc, argv);

  jkl::proto::ip::address server_address(server_address_string);
  if (server_address.get_version() ==
      jkl::proto::ip::address::version::e_none) {
    std::cerr << "incorrect address - " << server_address << std::endl;
    return -1;
  }

  fillTestData();
  std::atomic_bool work(true);
  std::vector<std::thread> worker_pool;
  for (size_t i = 0; i < threads_count; ++i) {
    worker_pool.push_back(std::thread(thread_fun, server_address, server_port,
                                      print_send_success, std::ref(work),
                                      connections_per_thread));
  }

  std::this_thread::sleep_for(std::chrono::seconds(test_time));
  work = false;
  for (auto &thr : worker_pool) thr.join();
}
