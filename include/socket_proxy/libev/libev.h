#pragma once
#include <ev.h>

namespace jkl::sp::ev {

struct ev_loop *init();
void proceed(struct ev_loop *loop);
void clean_up(struct ev_loop *&loop);
bool is_active(ev_io const &io_active);
void start(ev_io &active, struct ev_loop *loop);
void stop(ev_io &active, struct ev_loop *loop);

using io_callback_t = void (*)(struct ev_loop *loop, ev_io *watcher, int flags);
void init(ev_io &watcher, io_callback_t callback, int fd, int flags,
          void *connection);

}  // namespace jkl::sp::ev
