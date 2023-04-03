#pragma once
#include <vector>
#include <stddef.h>

namespace bro::net {

class buffer {
public:
  bool is_empty() const noexcept { return _buffer.empty(); }
  bool has_data() const noexcept { return !_buffer.empty(); }
  // NOTE: span doesn't work in my compiler
  std::pair<std::byte const *, size_t> get_data() const noexcept {
    if (has_data()) {
      return {_buffer.data(), _buffer.size()};
    }
    return {};
  }

  void append(std::byte const *data, size_t data_size) { _buffer.insert(_buffer.end(), data, data + data_size); }
  void pop_front(size_t n) {
    if (n >= _buffer.size()) {
      clear();
      return;
    }

    _buffer.erase(_buffer.begin(), _buffer.begin() + n);
  }

  void clear() { _buffer.clear(); }

private:
  std::vector<std::byte> _buffer;
};

} // namespace bro::net
