#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/sctp.h>
#include <network/libev/libev.h>
#include <network/sctp/settings.h>
#include <network/sctp/stream.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace bro::net::sctp {

void stream::set_socket_specific_options(proto::ip::address::version addr_ver)
{
    settings *params = (settings *) get_settings();
    /* Set the NODELAY option (Nagle-like algorithm) */
#ifdef SCTP_NODELAY
    int optval = 1;
    if (-1
        == ::setsockopt(_file_descr,
                        IPPROTO_SCTP,
                        SCTP_NODELAY,
                        reinterpret_cast<char const *>(&optval),
                        sizeof(optval))) {
        set_detailed_error("coulnd't set sctp nodelay option");
        set_connection_state(state::e_failed);
        return;
    }
#endif // SCTP_NODELAY

/* Set the retransmit parameters */
#ifdef SCTP_RTOINFO
    struct sctp_rtoinfo rtoinfo;
    memset(&rtoinfo, 0, sizeof(rtoinfo));
    /* rtoinfo.srto_initial: Estimate of the RTT before it can be measured; keep
   * the default value */
    rtoinfo.srto_max = params->_srto_max; /* Maximum retransmit timer (in ms), we
                                           want fast retransmission time. */
    rtoinfo.srto_min = params->_srto_min; /* Value under which the RTO does not descend, we set
                            this value to not conflict with srto_max */
    if (-1 == setsockopt(_file_descr, IPPROTO_SCTP, SCTP_RTOINFO, &rtoinfo, sizeof(rtoinfo))) {
        set_detailed_error("coulnd't set sctp retransmit parameters");
        set_connection_state(state::e_failed);
        return;
    }
#endif // SCTP_RTOINFO

/* Set the association parameters: max number of retransmits, ... */
#ifdef SCTP_ASSOCINFO
    struct sctp_assocparams assoc;
    memset(&assoc, 0, sizeof(assoc));
    assoc.sasoc_asocmaxrxt = params->_sasoc_asocmaxrxt; /* Maximum number of retransmission attempts:
                                    we want fast detection of errors */
    /* Note that this must remain less than the sum of retransmission parameters
   * of the different paths. */
    if (-1 == setsockopt(_file_descr, IPPROTO_SCTP, SCTP_ASSOCINFO, &assoc, sizeof(assoc))) {
        set_detailed_error("coulnd't set sctp maximum number of retransmit");
        set_connection_state(state::e_failed);
        return;
    }
#endif // SCTP_ASSOCINFO

/* Set the INIT parameters, such as number of streams */
#ifdef SCTP_INITMSG
    struct sctp_initmsg init;
    memset(&init, 0, sizeof(init));
    /* Set the init options -- need to receive SCTP_COMM_UP to confirm the
   * requested parameters, but we don't care (best effort) */
    init.sinit_num_ostreams = params->_sinit_num_ostreams; /* desired number of outgoing streams */
    init.sinit_max_init_timeo = params->_sinit_max_init_timeo;
    init.sinit_max_attempts = params->_sinit_max_attempts;
    init.sinit_max_instreams = params->_sinit_num_istreams;
    if (-1 == setsockopt(_file_descr, IPPROTO_SCTP, SCTP_INITMSG, &init, sizeof(init))) {
        set_detailed_error("coulnd't set sctp init message parameters");
        set_connection_state(state::e_failed);
        return;
    }
#endif // SCTP_INITMSG

/* The SO_LINGER option will be reset if we want to perform SCTP ABORT */
#ifdef SO_LINGER
    if (params->_reset_linger) {
        struct linger linger;
        memset(&linger, 0, sizeof(linger));
        linger.l_onoff = 0;  /* Do not activate the linger */
        linger.l_linger = 0; /* Ignored, but it would mean : Return immediately when closing (=>
              abort) (graceful shutdown in background) */
        if (-1 == setsockopt(_file_descr, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger))) {
            set_detailed_error("coulnd't set sctp so linger option");
            set_connection_state(state::e_failed);
            return;
        }
    }
#endif // SO_LINGER

    if (params->_use_mapped_v4_address) {
        if (proto::ip::address::version::e_v6 == addr_ver) {
            int v4mapped{0};
            //            v4mapped = 1;	/* but we may have to, otherwise the
            //            bind fails in some environments */
            ;
            if (-1 == setsockopt(_file_descr, IPPROTO_SCTP, SCTP_I_WANT_MAPPED_V4_ADDR, &v4mapped, sizeof(v4mapped))) {
                set_detailed_error("coulnd't enable mapped if v4 address for sctp");
                set_connection_state(state::e_failed);
                return;
            }
        }
    }

#ifdef SCTP_EVENTS

    struct sctp_event_subscribe event;
    memset(&event, 0, sizeof(event));
    event.sctp_data_io_event = params->_sctp_data_io_event;                   /* to receive the stream ID in SCTP_SNDRCV
                                                                                ancilliary data on message reception */
    event.sctp_association_event = params->_sctp_association_event;           /* new or closed associations (mostly for
                                                                               one-to-many style sockets) */
    event.sctp_address_event = params->_sctp_address_event;                   /* address changes */
    event.sctp_send_failure_event = params->_sctp_send_failure_event;         /* delivery failures */
    event.sctp_peer_error_event = params->_sctp_peer_error_event;             /* remote peer sends an error */
    event.sctp_shutdown_event = params->_sctp_shutdown_event;                 /* peer has sent a SHUTDOWN */
    event.sctp_partial_delivery_event = params->_sctp_partial_delivery_event; /* a partial delivery is aborted,
                                                                                 probably indicating the
                                                                                 connection is being shutdown */
    event.sctp_adaptation_layer_event = params->_sctp_adaptation_layer_event; /* adaptation layer notifications */
    event.sctp_authentication_event = params->_sctp_authentication_event;     /* when new key is made active */
    ;
    if (-1 == setsockopt(_file_descr, IPPROTO_SCTP, SCTP_EVENTS, &event, sizeof(event))) {
        set_detailed_error("coulnd't enable sctp events");
        set_connection_state(state::e_failed);
        return;
    }

#endif // SCTP_EVENTS

///* Set the SCTP_DISABLE_FRAGMENTS option, required for TLS */
#ifdef SCTP_DISABLE_FRAGMENTS
    if (params->_disable_frag) {
        int nofrag = 0;
        /* We turn ON the fragmentation, since Diameter  messages & TLS messages can be quite large. */
        if (-1 == setsockopt(_file_descr, IPPROTO_SCTP, SCTP_DISABLE_FRAGMENTS, &nofrag, sizeof(nofrag))) {
            set_detailed_error("coulnd't enable fragmentation for sctp messages");
            set_connection_state(state::e_failed);
            return;
        }
    }
#endif // SCTP_DISABLE_FRAGMENTS

/* SCTP_PEER_ADDR_PARAMS	control heartbeat per peer address. We set it as
 * a default for all addresses in the association; not sure if it works ... */
#ifdef SCTP_PEER_ADDR_PARAMS
    if (params->_enable_heart_beats) {
        struct sctp_paddrparams parms;
        memset(&parms, 0, sizeof(parms));
        parms.spp_address.ss_family = AF_INET;
        parms.spp_flags = SPP_HB_ENABLE; /* Enable heartbeat for the association */
#ifdef SPP_PMTUD_ENABLE
        parms.spp_flags |= SPP_PMTUD_ENABLE;            /* also enable path MTU discovery mechanism */
#endif                                                  /* SPP_PMTUD_ENABLE */
        parms.spp_hbinterval = params->_spp_hbinterval; /* Send an heartbeat every 6 seconds to quickly
                                                           start retransmissions */
        /* parms.spp_pathmaxrxt : max nbr of restransmissions on this address. There
         * is a relationship with sasoc_asocmaxrxt, so we leave the default here */

        /* Set the option to the socket */
        if (-1 == setsockopt(_file_descr, IPPROTO_SCTP, SCTP_PEER_ADDR_PARAMS, &parms, sizeof(parms))) {
            set_detailed_error("coulnd't enable sctp heart beats");
            set_connection_state(state::e_failed);
            return;
        };

#endif // SCTP_PEER_ADDR_PARAMS
    }
}

} // namespace bro::net::sctp
