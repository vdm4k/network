#pragma once

namespace bro::strm {
/** @addtogroup stream
 *  @{
 */

/**
 * \brief stream statistic interface
 */
struct statistic {
  virtual ~statistic(){};
  virtual void reset() = 0;
};

} // namespace bro::strm

/** @} */ // end of tratata2
