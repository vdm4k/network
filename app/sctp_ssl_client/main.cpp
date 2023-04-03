#include <network/stream/factory.h>
#include <network/sctp/ssl/send/settings.h>
#include <network/sctp/ssl/send/statistic.h>
#include <network/tcp/ssl/common.h>
#include <protocols/ip/full_address.h>

#include <atomic>
#include <iostream>
#include <thread>
#include <unordered_set>
#include <string.h>

#include "CLI/CLI.hpp"

bool print_debug_info = false;

using namespace bro::net;
using namespace bro::strm;

struct per_thread_data {
  std::thread _thread;
  sctp::ssl::send::statistic _stat;
};

void received_data_cb(stream *stream, std::any data_com) {
  const size_t data_size = 1500;
  std::byte data[data_size];
  ssize_t size = stream->receive(data, data_size);
  if (size == 0)
    return;
  if (size > 0) {
    if (print_debug_info)
      std::cout << "receive message - " << std::string((char *) data, size) << std::endl;
  }
  ssize_t const sent = stream->send(data, size);
  if (sent <= 0) {
    if (print_debug_info)
      std::cout << "send error - " << stream->get_detailed_error() << std::endl;
  }
}

void state_changed_cb(stream *stream, std::any data_com) {
  if (print_debug_info)
    std::cout << "state_changed_cb " << stream->get_state() << ", " << stream->get_detailed_error() << std::endl;
  if (!stream->is_active()) {
    auto *need_to_handle = std::any_cast<std::unordered_set<bro::strm::stream *> *>(data_com);
    need_to_handle->insert(stream);
  }
}

void fillTestData(int thread_number, std::vector<std::byte> &data_to_send, size_t data_size) {
  char send_data[] = {'c', 'l', 'i', 'e', 'n', 't', ' ', 'h', 'e', 'l', 'l', 'o', '!', ' ',
                      'f', 'r', 'o', 'm', ' ', 't', 'h', 'r', 'e', 'a', 'd', ' ', '-', ' '};
  data_to_send.assign((std::byte *) send_data, (std::byte *) send_data + sizeof(send_data));
  auto num = std::to_string(thread_number);
  data_to_send.insert(data_to_send.end(), (std::byte *) num.data(), (std::byte *) num.data() + num.size());
  if (data_size > data_to_send.size()) {
    std::vector<char> filler(data_size - data_to_send.size());
    std::iota(filler.begin(), filler.end(), 1);
    data_to_send.insert(data_to_send.end(), (std::byte *) filler.data(), (std::byte *) filler.data() + filler.size());
  }
}

void thread_fun(proto::ip::address const &server_addr,
                uint16_t server_port,
                std::atomic_bool &work,
                size_t connections_per_thread,
                size_t thread_number,
                sctp::ssl::send::statistic &stat,
                size_t data_size) {
  stream_factory manager;
  sctp::ssl::send::settings settings;
  settings._peer_addr = {server_addr, server_port};
  settings._non_blocking_socket = false;
  std::vector<std::byte> initial_data;
  fillTestData(thread_number, initial_data, data_size);
  std::unordered_set<stream *> need_to_handle;
  std::unordered_map<stream *, stream_ptr> stream_pool;

  while (work.load(std::memory_order_acquire)) {
    if (stream_pool.size() < connections_per_thread) {
      auto new_stream = manager.create_stream(&settings);
      if (new_stream->is_active()) {
        manager.bind(new_stream);
        new_stream->set_received_data_cb(::received_data_cb, nullptr);
        new_stream->set_state_changed_cb(::state_changed_cb, &need_to_handle);
        new_stream->send(initial_data.data(), initial_data.size());
        stream_pool[new_stream.get()] = std::move(new_stream);
      }
    }

    if (!need_to_handle.empty()) {
      auto it = need_to_handle.begin();
      if (!(*it)->is_active()) {
        stat += *static_cast<sctp::ssl::send::statistic const *>((*it)->get_statistic());
        stream_pool.erase((*it));
        need_to_handle.erase(it);
      }
    }

    manager.proceed();
  }

  for (auto &strm : stream_pool) {
    stat += *static_cast<sctp::ssl::send::statistic const *>(strm.first->get_statistic());
  }
}

int main(int argc, char **argv) {
  CLI::App app{"sctp_ssl_client"};
  std::string server_address_string;
  uint16_t server_port;
  size_t threads_count = 1;
  size_t test_time = 1; // in seconds
  size_t connections_per_thread = 1;
  size_t data_size = 1500;

  app.add_option("-a,--address", server_address_string, "server address")->required();
  app.add_option("-p,--port", server_port, "server port")->required();
  app.add_option("-j,--threads", threads_count, "threads count");
  app.add_option("-l,--log", print_debug_info, "print debug info");
  app.add_option("-d,--data", data_size, "send data size");
  app.add_option("-t,--test_time", test_time, "test time in seconds");
  app.add_option("-c,--connecions", connections_per_thread, "connections per thread");
  CLI11_PARSE(app, argc, argv);

  bro::net::tcp::ssl::disable_sig_pipe();

  proto::ip::address server_address(server_address_string);
  if (server_address.get_version() == proto::ip::address::version::e_none) {
    std::cerr << "incorrect address - " << server_address << std::endl;
    return -1;
  }

  std::cout << "client start" << std::endl;
  std::atomic_bool work(true);
  std::vector<per_thread_data> worker_pool;
  worker_pool.reserve(threads_count);
  for (size_t i = 0; i < threads_count; ++i) {
    worker_pool.emplace_back();
    auto &last = worker_pool.back();
    last._thread = std::thread(thread_fun,
                               server_address,
                               server_port,
                               std::ref(work),
                               connections_per_thread,
                               i,
                               std::ref(worker_pool.back()._stat),
                               data_size);
  }

  std::this_thread::sleep_for(std::chrono::seconds(test_time));
  work = false;
  sctp::ssl::send::statistic stat;
  for (auto &wrk : worker_pool) {
    wrk._thread.join();
    stat += wrk._stat;
  }

  std::cout << "client stoped" << std::endl;
  std::cout << "success_send_data - " << stat._success_send_data << std::endl;
  std::cout << "retry_send_data - " << stat._retry_send_data << std::endl;
  std::cout << "failed_send_data - " << stat._failed_send_data << std::endl;
  std::cout << "success_recv_data - " << stat._success_recv_data << std::endl;
  std::cout << "retry_recv_data - " << stat._retry_recv_data << std::endl;
  std::cout << "failed_recv_data - " << stat._failed_recv_data << std::endl;
}
