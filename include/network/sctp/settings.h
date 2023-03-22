#pragma once
#include <network/settings.h>
#include <stdint.h>

#include <optional>

namespace bro::net::sctp {
/** @addtogroup ev_stream
 *  @{
 */

/**
 * \brief common settings for listen/send sctp stream
 */
struct settings : public net::settings {
    enum ppid {
        e_plain_text = 46,
        e_ssl = 47
    };

    uint32_t _ppid = e_plain_text;              ///< https://tools.ietf.org/html/rfc6733 46 is for Diameter messages in clear text SCTP DATA chunks, and the PPID value 47
    uint16_t _srto_max = 5000;                  ///< Maximum retransmit timer (in ms), we want fast retransmission time.
    uint16_t _srto_min = 1000;                  ///< Value under which the RTO does not descend, we set this value to not conflict with srto_max
    uint16_t _sasoc_asocmaxrxt = 4;             ///< Maximum number of retransmission attempts: we want fast detection of errors
    uint16_t _sinit_num_ostreams    = 30;       ///< number of streams that the application wishes to be able to send to.
    uint16_t _sinit_num_istreams    = 0;        ///< the maximum number of inbound streams the application is prepared to support.
    uint16_t _sinit_max_attempts    = 2;        ///< how many attempts the SCTP endpoint should make at resending the INIT.
    uint16_t _sinit_max_init_timeo = 10000;     ///< the largest Time-Out or RTO value (in milliseconds) to use in attempting an INIT.
    uint16_t _spp_hbinterval = 6000;            ///< Send an heartbeat every 6 seconds to quickly start retransmissions
    uint8_t _sctp_data_io_event = 0;            ///< to receive the stream ID in SCTP_SNDRCV ancilliary data on message reception
    uint8_t _sctp_association_event = 0;        ///< new or closed associations (mostly for one-to-many style sockets)
    uint8_t _sctp_address_event = 0;            ///< address changes
    uint8_t _sctp_send_failure_event  = 1;      ///< delivery failures
    uint8_t _sctp_peer_error_event  = 0;        ///< remote peer sends an error
    uint8_t _sctp_shutdown_event  = 1;          ///< peer has sent a SHUTDOWN
    uint8_t _sctp_partial_delivery_event = 1;   ///< a partial delivery is aborted, probably indicating the connection is being shutdown
    uint8_t _sctp_authentication_event = 0;     ///< when new key is made active
    uint8_t _sctp_adaptation_layer_event = 0;   ///< adaptation layer notifications
    bool _disable_frag = false;                 ///< disable fragmentation
    bool _reset_linger = true;                  ///< The SO_LINGER option will be reset if we want to perform SCTP ABORT
    bool _use_mapped_v4_address = true;         ///< SCTP_I_WANT_MAPPED_V4_ADDR
    bool _enable_heart_beats = true;            ///< Enable heartbeat for the association
    bool _unordered = false;                    ///< Send/receive message unordered
};

}  // namespace bro::net::sctp

/** @} */  // end of ev_stream
