#include <protocols/ip/full_address.h>
#include <network/linux/ssl/send/settings.h>
#include <network/linux/ssl/send/statistic.h>
#include <network/linux/stream_factory.h>

#include <atomic>
#include <iostream>
#include <thread>
#include <unordered_set>

#include "CLI/CLI.hpp"

bool print_debug_info = false;
size_t data_size = 1500;
const size_t max_data_size = 65000;
thread_local std::byte send_data[max_data_size];

struct cb_data {
  bool *data_received = nullptr;
  std::unordered_set<bro::stream *> *_need_to_handle = nullptr;
};

struct per_stream_data {
  per_stream_data(bool received, bro::stream_ptr &&ptr)
      : data_received(received), stream(std::move(ptr)) {}
  bool data_received;
  bro::stream_ptr stream;
};

struct per_thread_data {
  std::unique_ptr<bro::sp::ev_stream_factory> _manager;
  std::unordered_map<bro::stream *, std::unique_ptr<per_stream_data>>
      _stream_pool;
  std::thread _thread;
  bro::sp::tcp::ssl::send::statistic _stat;
};

void received_data_cb(bro::stream *stream, std::any data_com) {
  cb_data cdata = std::any_cast<cb_data>(data_com);
  std::byte data[data_size];
  ssize_t size = stream->receive(data, data_size);
  if (size == 0) return;
  if (size > 0) {
    if (print_debug_info)
      std::cout << "receive message - " << std::string((char *)data, data_size)
                << std::endl;
  }
  *cdata.data_received = true;
}

void state_changed_cb(bro::stream *stream, std::any data_com) {
  if (print_debug_info)
    std::cout << "state_changed_cb " << stream->get_state() << ", "
              << stream->get_detailed_error() << std::endl;
  if (!stream->is_active()) {
    cb_data cdata = std::any_cast<cb_data>(data_com);
    cdata._need_to_handle->insert(stream);
  }
}

void send_data_cb(bro::stream *stream, std::any data_com) {
  if (print_debug_info) {
    std::cout << "data_sended " << std::endl;
  }
}

void fillTestData(int thread_number) {
  memset(send_data, 1, sizeof(send_data));
  char data[] = {'c', 'l', 'i', 'e', 'n', 't', ' ', 'h', 'e', 'l',
                 'l', 'o', '!', ' ', 'f', 'r', 'o', 'm', ' ', 't',
                 'h', 'r', 'e', 'a', 'd', ' ', '-', ' '};
  auto num = std::to_string(thread_number);
  memcpy(send_data, data, sizeof(data));
  memcpy(send_data + sizeof(data), num.c_str(), num.size());
}

void thread_fun(
    bro::proto::ip::address const &server_addr, uint16_t server_port,
    bool print_send_success, std::atomic_bool &work,
    size_t connections_per_thread, size_t th_num,
    bro::sp::tcp::ssl::send::statistic &stat,
    bro::sp::ev_stream_factory &manager,
    std::unordered_map<bro::stream *, std::unique_ptr<per_stream_data>>
        &stream_pool) {
  bro::sp::tcp::ssl::send::settings settings;
  settings._peer_addr = {server_addr, server_port};
  fillTestData(th_num);
  std::unordered_set<bro::stream *> _need_to_handle;

  while (work.load(std::memory_order_acquire)) {
    if (stream_pool.size() < connections_per_thread) {
      auto new_stream = manager.create_stream(&settings);
      if (new_stream->is_active()) {
        manager.bind(new_stream);
        auto s_data =
            std::make_unique<per_stream_data>(true, std::move(new_stream));
        cb_data cb_data{&s_data->data_received, &_need_to_handle};
        s_data->stream->set_received_data_cb(received_data_cb, cb_data);
        s_data->stream->set_state_changed_cb(state_changed_cb, cb_data);
        if (print_send_success)
          s_data->stream->set_send_data_cb(send_data_cb, nullptr);
        stream_pool[s_data->stream.get()] = std::move(s_data);
      }
    }

    for (auto &sp : stream_pool) {
      auto &per_stream_data = sp.second;
      auto &send_stream = per_stream_data->stream;
      if (bro::stream::state::e_established != send_stream->get_state() ||
          !per_stream_data->data_received)
        continue;

      per_stream_data->data_received = false;
      manager.proceed();
      send_stream->send(send_data, data_size);
    }

    if (!_need_to_handle.empty()) {
      auto it = _need_to_handle.begin();
      if (!(*it)->is_active()) {
        stat += *static_cast<bro::sp::tcp::ssl::send::statistic const *>(
            (*it)->get_statistic());
        stream_pool.erase((*it));
        _need_to_handle.erase(it);
      }
    }

    manager.proceed();
  }
}

int main(int argc, char **argv) {
  CLI::App app{"ssl_client"};
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

  bro::proto::ip::address server_address(server_address_string);
  if (server_address.get_version() ==
      bro::proto::ip::address::version::e_none) {
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
    last._manager = std::make_unique<bro::sp::ev_stream_factory>();
    last._thread =
        std::thread(thread_fun, server_address, server_port, print_send_success,
                    std::ref(work), connections_per_thread, i,
                    std::ref(worker_pool.back()._stat),
                    std::ref(*worker_pool.back()._manager),
                    std::ref(worker_pool.back()._stream_pool));
  }

  std::this_thread::sleep_for(std::chrono::seconds(test_time));
  work = false;
  bro::sp::tcp::ssl::send::statistic stat;
  for (auto &wrk : worker_pool) {
    wrk._thread.join();
    stat += wrk._stat;
    for (auto &strm : wrk._stream_pool) {
      stat += *static_cast<bro::sp::tcp::ssl::send::statistic const *>(
          strm.first->get_statistic());
    }
  }

  std::cout << "client stoped" << std::endl;
  std::cout << "success_send_data - " << stat._success_send_data << std::endl;
  std::cout << "retry_send_data - " << stat._retry_send_data << std::endl;
  std::cout << "failed_send_data - " << stat._failed_send_data << std::endl;
  std::cout << "success_recv_data - " << stat._success_recv_data << std::endl;
  std::cout << "retry_recv_data - " << stat._retry_recv_data << std::endl;
  std::cout << "failed_recv_data - " << stat._failed_recv_data << std::endl;
}
