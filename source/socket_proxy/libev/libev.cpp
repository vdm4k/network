#include <ev.h>
#include <socket_proxy/libev/libev.h>

#include <climits>
#include <string>

namespace jkl::sp::ev {

struct ev_loop *init() {
  return ev_loop_new(EVFLAG_AUTO);
}

void clean_up(struct ev_loop *&loop) {
  ev_loop_destroy(loop);
  loop = nullptr;
}

bool is_active(struct ev_io const *io_active) { return 0 != io_active->active; }

void start(struct ev_io &active, struct ev_loop *loop) {
  if (!is_active(&active)) {
    ev_io_start(loop, &active);
  }
}

void stop(struct ev_io &active, struct ev_loop *loop) {
  if (is_active(&active)) {
    ev_io_stop(loop, &active);
  }
}

void init(ev_io &watcher, io_callback_t callback, int fd, int flags,
          void *connection) {
  memset(&watcher, 0, sizeof(watcher));
  watcher.fd = fd;
  watcher.cb = callback;
  watcher.events = flags | EV__IOFDSET;
  watcher.data = connection;
}

void proceed(struct ev_loop *loop) { ev_loop(loop, EVRUN_ONCE | EVRUN_NOWAIT); }

}  // namespace jkl::sp::ev
