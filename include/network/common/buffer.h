#pragma once
#include <vector>
#include <stddef.h>

namespace bro::net {

/** @defgroup common common
 *  @{
 */

/*! \brief A class that represents a buffer of bytes.
 *  The buffer class is a simple implementation of a byte buffer that allows appending and removing bytes
 */
class buffer {
public:
  /*! \brief  Checks if the buffer is empty.
   * \return True if the buffer is empty, false otherwise.
 */
  bool is_empty() const noexcept { return _buffer.empty(); }

  /*! @brief Gets a pair of pointers to the data in the buffer and the size of the buffer.
  * If the buffer has data, this method returns a pair of pointers to the data in the buffer and the size of the buffer.
  * If the buffer is empty, it returns an empty pair.
  * \return A pair of pointers to the data in the buffer and the size of the buffer.
  *
  * \note span doesn't work in my compiler
 */
  std::pair<std::byte const *, size_t> get_data() const noexcept {
    if (!is_empty()) {
      return {_buffer.data(), _buffer.size()};
    }
    return {};
  }

  /*! \brief Appends data to the end of the buffer.
   * \param data A pointer to the data to append.
   * \param data_size The size of the data to append.
   */
  void append(std::byte const *data, size_t data_size) { _buffer.insert(_buffer.end(), data, data + data_size); }

  /*! \brief  Removes data from the front of the buffer.
   *  If the size of data to be removed is greater than or equal to the size of the buffer, the buffer is cleared.
   * \param n The number of bytes to remove from the front of the buffer.
 */
  void erase(size_t n) {
    if (n >= _buffer.size()) {
      clear();
      return;
    }

    _buffer.erase(_buffer.begin(), _buffer.begin() + n);
  }

  /*! \brief  Clears the buffer.
  */
  void clear() { _buffer.clear(); }

private:
  std::vector<std::byte> _buffer; ///< The underlying byte buffer.
};

} // namespace bro::net
