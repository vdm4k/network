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

  /*! \brief reset statistics
   */
  virtual void reset() = 0;
};

} // namespace bro::strm
