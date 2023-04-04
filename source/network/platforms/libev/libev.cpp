#include <ev.h>
#include <network/platforms/libev/libev.h>

#include <climits>
#include <string>

namespace bro::net::ev {

struct ev_loop *init() {
  return ev_loop_new(EVFLAG_AUTO);
}

void proceed(struct ev_loop *loop) {
  ev_loop(loop, EVRUN_ONCE | EVRUN_NOWAIT);
}

void clean_up(struct ev_loop *&loop) {
  ev_loop_destroy(loop);
  loop = nullptr;
}

bool is_active(struct ev_io const &io) {
  return 0 != io.active;
}

void start(struct ev_io &io, struct ev_loop *loop) {
  if (!is_active(io)) {
    ev_io_start(loop, &io);
  }
}

void stop(struct ev_io &io, struct ev_loop *loop) {
  if (is_active(io)) {
    ev_io_stop(loop, &io);
  }
}

void init_io(ev_io &io, io_callback_t callback, int file_descriptor, int flags, void *user_data) {
  memset(&io, 0, sizeof(io));
  io.fd = file_descriptor;
  io.cb = callback;
  io.events = flags | EV__IOFDSET;
  io.data = user_data;
}

} // namespace bro::net::ev
