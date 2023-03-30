#include <network/stream_factory.h>
#include <network/tcp/ssl/send/settings.h>
#include <network/tcp/ssl/send/statistic.h>
#include <protocols/ip/full_address.h>

#include <atomic>
#include <iostream>
#include <thread>
#include <unordered_set>
#include <string.h>

#include "CLI/CLI.hpp"

using namespace bro::net;
using namespace bro::strm;

bool print_debug_info = false;

struct per_stream_data {
  per_stream_data(stream_ptr &&ptr, std::unordered_set<bro::strm::stream *> *need_to_handle)
    : stream(std::move(ptr))
    , _need_to_handle(need_to_handle) {}

  bro::strm::stream_ptr stream;
  std::unordered_set<bro::strm::stream *> *_need_to_handle = nullptr;
  std::vector<std::byte> _unsent_data;
};

struct per_thread_data {
  std::unique_ptr<ev_stream_factory> _manager;
  std::unordered_map<stream *, std::unique_ptr<per_stream_data>> _stream_pool;
  std::thread _thread;
  tcp::ssl::send::statistic _stat;
};

void write_data_cb(stream *stream, std::any data_com) {
  auto *cdata = std::any_cast<per_stream_data *>(data_com);
  if (cdata->_unsent_data.empty()) {
    stream->set_send_data_cb(nullptr, nullptr);
    return;
  }

  ssize_t size = stream->send(cdata->_unsent_data.data(), cdata->_unsent_data.size());
  if (size == 0)
    return;
  if (size > 0) {
    if (size == cdata->_unsent_data.size()) {
      cdata->_unsent_data.clear();
      stream->set_send_data_cb(nullptr, nullptr);
      return;
    }
    cdata->_unsent_data.erase(cdata->_unsent_data.begin(), cdata->_unsent_data.begin() + size);
    return;
  }

  if (size < 0) {
    if (print_debug_info)
      std::cout << "send error - " << stream->get_detailed_error() << std::endl;
  }
}

void received_data_cb(stream *stream, std::any data_com) {
  per_stream_data *cdata = std::any_cast<per_stream_data *>(data_com);
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
  if (sent == 0) {
    cdata->_unsent_data.insert(cdata->_unsent_data.end(), data, data + size);
    stream->set_send_data_cb(::write_data_cb, data_com);
    return;
  }
  if (sent <= 0) {
    if (print_debug_info)
      std::cout << "send error - " << stream->get_detailed_error() << std::endl;
  }
}

void state_changed_cb(stream *stream, std::any data_com) {
  if (print_debug_info)
    std::cout << "state_changed_cb " << stream->get_state() << ", " << stream->get_detailed_error() << std::endl;
  if (!stream->is_active()) {
    per_stream_data *cdata = std::any_cast<per_stream_data *>(data_com);
    cdata->_need_to_handle->insert(stream);
  }
}

void send_data_cb(stream *stream, std::any data_com) {
  if (print_debug_info) {
    std::cout << "data_sended " << std::endl;
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
                bool print_send_success,
                std::atomic_bool &work,
                size_t connections_per_thread,
                size_t th_num,
                tcp::ssl::send::statistic &stat,
                ev_stream_factory &manager,
                std::unordered_map<stream *, std::unique_ptr<per_stream_data>> &stream_pool,
                size_t data_size) {
  tcp::ssl::send::settings settings;
  settings._peer_addr = {server_addr, server_port};
  std::unordered_set<stream *> _need_to_handle;

  while (work.load(std::memory_order_acquire)) {
    if (stream_pool.size() < connections_per_thread) {
      auto new_stream = manager.create_stream(&settings);
      if (new_stream->is_active()) {
        manager.bind(new_stream);
        auto s_data = std::make_unique<per_stream_data>(std::move(new_stream), &_need_to_handle);
        fillTestData(th_num, s_data->_unsent_data, data_size);
        s_data->stream->set_received_data_cb(::received_data_cb, s_data.get());
        s_data->stream->set_state_changed_cb(::state_changed_cb, s_data.get());
        s_data->stream->set_send_data_cb(::write_data_cb, s_data.get());
        stream_pool[s_data->stream.get()] = std::move(s_data);
      }
    }

    if (!_need_to_handle.empty()) {
      auto it = _need_to_handle.begin();
      if (!(*it)->is_active()) {
        stat += *static_cast<tcp::ssl::send::statistic const *>((*it)->get_statistic());
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
  size_t test_time = 1; // in seconds
  size_t connections_per_thread = 1;
  size_t data_size = 1500;

  app.add_option("-a,--address", server_address_string, "server address")->required();
  app.add_option("-p,--port", server_port, "server port")->required();
  app.add_option("-j,--threads", threads_count, "threads count");
  app.add_option("-l,--log", print_debug_info, "print debug info");
  app.add_option("-d,--data", data_size, "send data size");
  app.add_option("-w,--send_success", print_send_success, "print send success");
  app.add_option("-t,--test_time", test_time, "test time in seconds");
  app.add_option("-c,--connecions", connections_per_thread, "connections per thread");
  CLI11_PARSE(app, argc, argv);

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
    last._manager = std::make_unique<ev_stream_factory>();
    last._thread = std::thread(thread_fun,
                               server_address,
                               server_port,
                               print_send_success,
                               std::ref(work),
                               connections_per_thread,
                               i,
                               std::ref(worker_pool.back()._stat),
                               std::ref(*worker_pool.back()._manager),
                               std::ref(worker_pool.back()._stream_pool),
                               data_size);
  }

  std::this_thread::sleep_for(std::chrono::seconds(test_time));
  work = false;
  tcp::ssl::send::statistic stat;
  for (auto &wrk : worker_pool) {
    wrk._thread.join();
    stat += wrk._stat;
    for (auto &strm : wrk._stream_pool) {
      stat += *static_cast<tcp::ssl::send::statistic const *>(strm.first->get_statistic());
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
