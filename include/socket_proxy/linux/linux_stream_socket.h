#pragma once
#include <socket_proxy/stream_socket.h>

namespace jkl::sp::lnx {

class stream_socket : public jkl::sp::stream_socket {
 public:
  ~stream_socket();

  /*! \fn send_result send(void const * ptr, size_t len)
   *  \brief send data
   *  \param [in] ptr pointer on data
   *  \param [in] len data lenght
   *  \return send_result if send_result is positive - sended data size
   *      otherwise send_result interpet as error
   */
  send_result send(void *data, size_t size) override;

  /*! \fn receive_result receive(uint8_t *data, size_t size)
   *  \brief receive data
   *  \param [in] ptr pointer on buffer
   *  \param [in] len buffer lenght
   *  \return receive_result if receive_result is positive - received data size
   *      otherwise receive_result interpet as error
   */
  receive_result receive(uint8_t *data, size_t size) override;

  /*! \fn faddresses const& get_self_address() const
   *  \brief
   *  \return return self address
   */
  jkl::proto::ip_addr const &get_self_address() const override;

  /*! \fn faddresses const& get_peer_address() const
   *  \brief
   *  \return return peer address
   */
  jkl::proto::ip_addr const &get_peer_address() const override;

  /*! \fn std::string const & get_detailed_error() const
   *  \brief get description about error
   *  \return std::string description
   */
  std::string const &get_detailed_error() const override;

  /*! \fn connection_state get_state() const
   *  \brief socket state
   *  \return connection_state
   */
  connection_state get_state() const override;

  /*! \fn stream_type get_type() const
   *  \brief get stream type
   *  \return stream_type
   */
  stream_type get_type() const override;

  /*! \brief set callback on data receive
   *  \param [in] received_data_cb pointer on callback function if nullptr - non
   * active
   * \param [in] first_param first parameter for callback function
   * \param [in] sec_param second parameter for callback function
   */
  void set_received_data_cb(received_data_cb cb, void *first_param,
                            void *sec_param) override;

  /*! \brief set callback on data receive
   *  \param [in] send_data_cb pointer on callback function if nullptr - non
   * active
   * \param [in] first_param first parameter for callback function
   * \param [in] second_param second parameter for callback function
   */
  void set_send_data_cb(send_data_cb cb, void *first_param,
                        void *second_param) override;

  /*! \brief set callback on data receive
   *  \param [in] set_state_changed_cb pointer on callback function if nullptr -
   * non active
   * \param [in] first_param first parameter for callback function
   * \param [in] second_param second parameter for callback function
   */
  void set_state_changed_cb(state_changed_cb cb, void *first_param,
                            void *second_param) override;

 private:
  std::string _error;
  received_data_cb _received_data_cb = nullptr;
  void *_f_param_rec_cb = nullptr;
  void *_s_param_rec_cb = nullptr;
  send_data_cb _send_data_cb = nullptr;
  void *_f_param_send_cb = nullptr;
  void *_s_param_send_cb = nullptr;
  state_changed_cb _state_changed_cb = nullptr;
  void *_f_param_sc_cb = nullptr;
  void *_s_param_sc_cb = nullptr;
};

using stream_socket_ptr = std::unique_ptr<stream_socket>;

}  // namespace jkl::sp::lnx
