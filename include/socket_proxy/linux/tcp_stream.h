#pragma once
#include <arpa/inet.h>
#include <protocols/full_address.h>
#include <socket_proxy/linux/tcp_settings.h>
#include <socket_proxy/stream.h>

#include <string>

#include "ev.h"

/** @addtogroup stream
 *  @{
 */

namespace jkl::sp::lnx {

class tcp_stream : public stream {
 public:
  ~tcp_stream();
  tcp_stream() = default;
  tcp_stream(tcp_stream const &) = delete;
  tcp_stream(tcp_stream &&) = delete;
  tcp_stream &operator=(tcp_stream &&) = delete;
  tcp_stream &operator=(tcp_stream const &) = delete;

  /*! \fn send_result send(void const * ptr, size_t len)
   *  \brief send data
   *  \param [in] ptr pointer on data
   *  \param [in] len data lenght
   *  \return send_result if send_result is positive - sended data size
   *      otherwise send_result interpet as error
   */
  ssize_t send(std::byte *data, size_t data_size) override;

  /*! \fn receive_result receive(uint8_t *data, size_t size)
   *  \brief receive data
   *  \param [in] ptr pointer on buffer
   *  \param [in] len buffer lenght
   *  \return receive_result if receive_result is positive - received data size
   *      otherwise receive_result interpet as error
   */
  ssize_t receive(std::byte *data, size_t data_size) override;

  /*! \fn faddresses const& get_self_address() const
   *  \brief
   *  \return return self address
   */
  jkl::proto::full_address const &get_self_address() const;

  /*! \fn faddresses const& get_peer_address() const
   *  \brief
   *  \return return peer address
   */
  jkl::proto::full_address const &get_peer_address() const;

  /*! \fn std::string const & get_detailed_error() const
   *  \brief get description about error
   *  \return std::string description
   */
  std::string const &get_detailed_error() const override;

  /*! \fn connection_state get_state() const
   *  \brief socket state
   *  \return connection_state
   */
  state get_state() const override;

  /*! \brief set callback on data receive
   *  \param [in] received_data_cb pointer on callback function if nullptr - non
   * active
   * \param [in] param parameter for callback function
   */
  void set_received_data_cb(received_data_cb cb, std::any param) override;

  /*! \brief set callback on data receive
   *  \param [in] send_data_cb pointer on callback function if nullptr - non
   * active
   * \param [in] param parameter for callback function
   */
  void set_send_data_cb(send_data_cb cb, std::any param) override;

  /*! \brief set callback on data receive
   *  \param [in] set_state_changed_cb pointer on callback function if nullptr -
   * non active
   * \param [in] param parameter for callback function
   */
  void set_state_changed_cb(state_changed_cb cb, std::any param) override;

  bool connect_to_server(send_stream_socket_parameters *send_params,
                         struct ev_loop *loop);
  bool bind_as_server(listen_stream_socket_parameters *listen_params,
                      struct ev_loop *loop);

 protected:
  bool fill_addr(jkl::proto::full_address const &faddr, sockaddr_in &addr);
  void init_events(struct ev_loop *loop);
  void set_connection_state(state st);
  void set_detailed_error(const std::string &str);
  void cleanup();
  bool create_socket();

 private:
  void stop_events();
  void receive_data();
  void send_data();
  void connection_established();
  void set_socket_specific_options();

  bool create_listen_tcp_socket();

  friend void receive_data_cb(struct ev_loop *, ev_io *w, int);
  friend void send_data_cb(struct ev_loop *, ev_io *w, int);
  friend void connection_established_cb(struct ev_loop *, ev_io *w, int);

 protected:
  sockaddr_in _peer_addr;
  ev_io _connect_io;
  int _file_descr = -1;
  struct ev_loop *_loop = nullptr;
  friend class tcp_listen_stream;

 private:
  ev_io _read_io;
  ev_io _write_io;
  std::string _error;
  received_data_cb _received_data_cb;
  std::any _param_received_data_cb;
  send_data_cb _send_data_cb;
  std::any _param_send_data_cb;
  state_changed_cb _state_changed_cb;
  std::any _param_state_changed_cb;

  sockaddr_in _self_addr;
  std::string _detailed_error;
  state _state = state::e_closed;
};

using stream_socket_ptr = std::unique_ptr<tcp_stream>;

class tcp_send_stream : public tcp_stream {
 public:
  bool init(send_stream_socket_parameters *send_params, struct ev_loop *loop);
  bool connect();

  stream_settings const *get_stream_settings() const override {
    return &_send_stream_socket_parameters;
  }

 private:
  send_stream_socket_parameters _send_stream_socket_parameters;
};

class tcp_listen_stream : public tcp_stream {
 public:
  bool init(listen_stream_socket_parameters *send_params, struct ev_loop *loop);

  stream_settings const *get_stream_settings() const override {
    return &_listen_stream_socket_parameters;
  }

 private:
  friend void incoming_connection_cb(struct ev_loop * /*loop*/, ev_io *w,
                                     int /*revents*/);
  void handle_incoming_connection(int file_descr, sockaddr_in peer_addr);
  listen_stream_socket_parameters _listen_stream_socket_parameters;
};

}  // namespace jkl::sp::lnx

/** @} */  // end of stream
