#pragma once
#include <protocols/ip_addr.h>

#include <memory>

namespace jkl {
namespace sp {

using received_data_cb = void (*)(void *,
                                  void *);      ///< callback on receive data
using send_data_cb = void (*)(void *, void *);  ///< callback on send data
using state_changed_cb = void (*)(void *,
                                  void *);  ///< callback on state change

class stream_socket {
 public:
  /*!
   * @brief stream type
   */
  enum class stream_type : uint8_t {
    e_tcp  ///< tcp
  };

  /*!
   * @brief stream state
   */
  enum class connection_state : uint8_t {
    e_closed,       ///< closed - not active
    e_listen,       ///< for server side connection in listen state
                    ///< for client wait establishing with peer
    e_established,  ///< connection established
    e_failed        ///< connection failed, can check error with
                    ///< get_detailed_error
  };

  enum send_result : int {
    e_send_error = -1  ///< send error
  };

  enum receive_result : int {
    e_rec_error = -1  ///< receive error
  };

  virtual ~stream_socket() = default;

  /*! \fn send_result send(void const * ptr, size_t len)
   *  \brief send data
   *  \param [in] ptr pointer on data
   *  \param [in] len data lenght
   *  \return send_result if send_result is positive - sended data size
   *      otherwise send_result interpet as error
   */
  virtual send_result send(void *data, size_t size) = 0;

  /*! \fn receive_result receive(uint8_t *data, size_t size)
   *  \brief receive data
   *  \param [in] ptr pointer on buffer
   *  \param [in] len buffer lenght
   *  \return receive_result if receive_result is positive - received data size
   *      otherwise receive_result interpet as error
   */
  virtual receive_result receive(uint8_t *data, size_t size) = 0;

  /*! \fn faddresses const& get_self_address() const
   *  \brief
   *  \return return self address
   */
  virtual jkl::proto::ip_addr const &get_self_address() const = 0;

  /*! \fn faddresses const& get_peer_address() const
   *  \brief
   *  \return return peer address
   */
  virtual jkl::proto::ip_addr const &get_peer_address() const = 0;

  /*! \fn std::string const & get_detailed_error() const
   *  \brief get description about error
   *  \return std::string description
   */
  virtual std::string const &get_detailed_error() const = 0;

  /*! \fn connection_state get_state() const
   *  \brief socket state
   *  \return connection_state
   */
  virtual connection_state get_state() const = 0;

  /*! \fn stream_type get_type() const
   *  \brief get stream type
   *  \return stream_type
   */
  virtual stream_type get_type() const = 0;

  /*! \brief set callback on data receive
   *  \param [in] received_data_cb pointer on callback function if nullptr - non
   * active
   * \param [in] first_param first parameter for callback function
   * \param [in] second_param second parameter for callback function
   */
  virtual void set_received_data_cb(received_data_cb cb, void *first_param,
                                    void *second_param) = 0;

  /*! \brief set callback on data receive
   *  \param [in] send_data_cb pointer on callback function if nullptr - non
   * active
   * \param [in] first_param first parameter for callback function
   * \param [in] second_param second parameter for callback function
   */
  virtual void set_send_data_cb(send_data_cb cb, void *first_param,
                                void *second_param) = 0;

  /*! \brief set callback on data receive
   *  \param [in] set_state_changed_cb pointer on callback function if nullptr -
   * non active
   * \param [in] first_param first parameter for callback function
   * \param [in] second_param second parameter for callback function
   */
  virtual void set_state_changed_cb(state_changed_cb cb, void *first_param,
                                    void *second_param) = 0;
};

using stream_socket_ptr = std::unique_ptr<stream_socket>;

}  // namespace sp
}  // namespace jkl
