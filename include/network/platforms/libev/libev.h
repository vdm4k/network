#pragma once
#include <ev.h>

namespace bro::net::ev {

/** @defgroup libev libev
 *  @{
 */

/*! \brief create new event loop
 *  \result pointer on event loop
 */
struct ev_loop *init();

/*! \brief proceed event loop
 *  \param loop to proceed
 */
void proceed(struct ev_loop *loop);

/*! \brief cleanup event loop
 *  \result pointer on event loop
 */
void clean_up(struct ev_loop *&loop);

/*! \brief check if current io is active
 *  \param io to check
 *  \result true on succes. false otherwise
 */
bool is_active(ev_io const &io);

/*! \brief start io on specific event loop
 *  \param io to start
 *  \param loop - main event loop
 */
void start(ev_io &io, struct ev_loop *loop);

/*! \brief stop io on event loop
 *  \param io to start
 *  \param loop - main event loop
 */
void stop(ev_io &io, struct ev_loop *loop);

using io_callback_t = void (*)(struct ev_loop *loop, ev_io *watcher,
                               int flags); ///< io callback type
/*! \brief init io with specific parameters
 *  \param io to feel
 *  \param callback that will be called
 *  \param file_descriptor on which will be processing
 *  \param flags - event type
 *  \param user_data on associated data
 */
void init_io(ev_io &io, io_callback_t callback, int file_descriptor, int flags, void *user_data);

} // namespace bro::net::ev
