/*
 * Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>
 *
 * This file is part of Open5GS.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "gtp-path.h"

static ogs_pkbuf_pool_t *packet_pool = NULL;

static void _gtpv1_u_recv_cb(short when, ogs_socket_t fd, void *data)
{
#if 0
    char buf[OGS_ADDRSTRLEN];
    int rv;
    ssize_t size;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sockaddr_t from;
    ogs_gtp_header_t *gtp_h = NULL;
    sgwu_bearer_t *bearer = NULL;
#if 0
    sgwu_tunnel_t *tunnel = NULL;
#endif
    uint32_t teid;
    int i;

    ogs_assert(fd != INVALID_SOCKET);
    ogs_assert(packet_pool);

    pkbuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_SDU_LEN);
    ogs_pkbuf_put(pkbuf, OGS_MAX_SDU_LEN);

    size = ogs_recvfrom(fd, pkbuf->data, pkbuf->len, 0, &from);
    if (size <= 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "ogs_recvfrom() failed");
        ogs_pkbuf_free(pkbuf);
        return;
    }

    ogs_pkbuf_trim(pkbuf, size);

    gtp_h = (ogs_gtp_header_t *)pkbuf->data;
    if (gtp_h->type == OGS_GTPU_MSGTYPE_ECHO_REQ) {
        ogs_pkbuf_t *echo_rsp;

        ogs_debug("[SGW] RECV Echo Request from [%s]",
                OGS_ADDR(&from, buf));
        echo_rsp = ogs_gtp_handle_echo_req(pkbuf);
        if (echo_rsp) {
            ssize_t sent;

            /* Echo reply */
            ogs_debug("[SGW] SEND Echo Response to [%s]",
                    OGS_ADDR(&from, buf));

            sent = ogs_sendto(fd, echo_rsp->data, echo_rsp->len, 0, &from);
            if (sent < 0 || sent != echo_rsp->len) {
                ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                        "ogs_sendto() failed");
            }
            ogs_pkbuf_free(echo_rsp);
        }
    } else if (gtp_h->type == OGS_GTPU_MSGTYPE_GPDU || 
                gtp_h->type == OGS_GTPU_MSGTYPE_END_MARKER) {
        teid = ntohl(gtp_h->teid);
        if (gtp_h->type == OGS_GTPU_MSGTYPE_GPDU)
            ogs_debug("[SGW] RECV GPU-U from [%s] : TEID[0x%x]",
                    OGS_ADDR(&from, buf), teid);
        else if (gtp_h->type == OGS_GTPU_MSGTYPE_END_MARKER)
            ogs_debug("[SGW] RECV End Marker from [%s] : TEID[0x%x]",
                    OGS_ADDR(&from, buf), teid);

        tunnel = sgwu_tunnel_find_by_teid(teid);
        if (!tunnel) {
            if (gtp_h->type == OGS_GTPU_MSGTYPE_GPDU)
                ogs_warn("[SGW] RECV GPU-U from [%s] : No TEID[0x%x]",
                        OGS_ADDR(&from, buf), teid);
            else if (gtp_h->type == OGS_GTPU_MSGTYPE_END_MARKER)
                ogs_warn("[SGW] RECV End Marker from [%s] : No TEID[0x%x]",
                        OGS_ADDR(&from, buf), teid);
            ogs_pkbuf_free(pkbuf);
            return;
        }
        bearer = tunnel->bearer;
        ogs_assert(bearer);

        /* Convert TEID */
        if (tunnel->interface_type == OGS_GTP_F_TEID_S1_U_SGW_GTP_U) {
            sgwu_tunnel_t *s5u_tunnel = NULL;

            s5u_tunnel = sgwu_s5u_tunnel_in_bearer(bearer);
            ogs_assert(s5u_tunnel);
            ogs_assert(s5u_tunnel->gnode);
            ogs_assert(s5u_tunnel->gnode->sock);
            ogs_debug("[SGW] SEND GPU-U to PGW[%s]: TEID[0x%x]",
                OGS_ADDR(&s5u_tunnel->gnode->addr, buf),
                s5u_tunnel->remote_teid);

            gtp_h->teid = htonl(s5u_tunnel->remote_teid);
            ogs_gtp_sendto(s5u_tunnel->gnode, pkbuf);
        } else if (tunnel->interface_type ==
                    OGS_GTP_F_TEID_SGW_GTP_U_FOR_DL_DATA_FORWARDING ||
                tunnel->interface_type ==
                    OGS_GTP_F_TEID_SGW_GTP_U_FOR_UL_DATA_FORWARDING) {
            sgwu_tunnel_t *indirect_tunnel = NULL;

            indirect_tunnel = sgwu_tunnel_find_by_interface_type(bearer,
                    tunnel->interface_type);
            ogs_assert(indirect_tunnel);
            ogs_assert(indirect_tunnel->gnode);
            ogs_assert(indirect_tunnel->gnode->sock);
            ogs_debug("[SGW] SEND GPU-U to Indirect Tunnel[%s]: TEID[0x%x]",
                OGS_ADDR(&indirect_tunnel->gnode->addr, buf),
                indirect_tunnel->remote_teid);

            gtp_h->teid = htonl(indirect_tunnel->remote_teid);
            ogs_gtp_sendto(indirect_tunnel->gnode, pkbuf);
        } else if (tunnel->interface_type == OGS_GTP_F_TEID_S5_S8_SGW_GTP_U) {
            sgwu_tunnel_t *s1u_tunnel = NULL;

            s1u_tunnel = sgwu_s1u_tunnel_in_bearer(bearer);
            ogs_assert(s1u_tunnel);

            if (s1u_tunnel->remote_teid) {
                ogs_assert(s1u_tunnel->gnode);
                ogs_assert(s1u_tunnel->gnode->sock);
                ogs_debug("[SGW] SEND GPU-U to ENB[%s]: TEID[0x%x]",
                    OGS_ADDR(&s1u_tunnel->gnode->addr, buf),
                    s1u_tunnel->remote_teid);

                /* If there is buffered packet, send it first */
                for (i = 0; i < bearer->num_buffered_pkt; i++) {
                    ogs_gtp_header_t *gtp_h = NULL;

                    gtp_h = (ogs_gtp_header_t *)bearer->buffered_pkts[i]->data;
                    gtp_h->teid = htonl(s1u_tunnel->remote_teid);

                    ogs_gtp_sendto(s1u_tunnel->gnode, bearer->buffered_pkts[i]);
                    ogs_pkbuf_free(bearer->buffered_pkts[i]);
                }
                bearer->num_buffered_pkt = 0;

                gtp_h->teid = htonl(s1u_tunnel->remote_teid);
                ogs_gtp_sendto(s1u_tunnel->gnode, pkbuf);
            } else {
                /* S1U path is deactivated.
                 * Send downlink_data_notification to MME.
                 *
                 */
                sgwu_ue_t *sgwu_ue = NULL;

                ogs_assert(bearer->sess);
                ogs_assert(bearer->sess->sgwu_ue);

                sgwu_ue = bearer->sess->sgwu_ue;

                ogs_debug("[SGW] S1U PATH deactivated : STATE[0x%x]",
                        SGW_GET_UE_STATE(sgwu_ue));
                if ((SGW_GET_UE_STATE(sgwu_ue) & SGW_S1U_INACTIVE)) {
                    ogs_debug("    SGW-S1U Inactive");
                    if (!(SGW_GET_UE_STATE(sgwu_ue) & SGW_DL_NOTI_SENT)) {
                        sgwu_event_t *e;

                        ogs_debug("    EVENT DL Data Notification");
                        e = sgwu_event_new(SGWU_EVT_LO_DLDATA_NOTI);
                        ogs_assert(e);
                        e->bearer = bearer;
                        rv = ogs_queue_push(sgwu_self()->queue, e);
                        if (rv != OGS_OK) {
                            ogs_error("ogs_queue_push() failed:%d", (int)rv);
                            sgwu_event_free(e);
                        }

                        SGW_SET_UE_STATE(sgwu_ue, SGW_DL_NOTI_SENT);
                    }

                    /* Buffer the packet */
                    if (bearer->num_buffered_pkt < MAX_NUM_OF_PACKET_BUFFER) {
                        bearer->buffered_pkts[bearer->num_buffered_pkt++] = 
                            pkbuf;
                        return;
                    }
                } else {
                    /* UE is S1U_ACTIVE state but there is no s1u teid */
                    ogs_debug("[SGW] UE is ACITVE but there is no matched "
                            "ENB_S1U_TEID[%d]", teid);

                    /* Just drop it */
                }
            }
        }
    }

    ogs_pkbuf_free(pkbuf);
    return;
#endif
    int rv, len;
    ssize_t size;
    char buf[OGS_ADDRSTRLEN];

    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sockaddr_t from;

    ogs_gtp_header_t *gtp_h = NULL;
    struct ip *ip_h = NULL;

    uint32_t teid;
    uint8_t qfi;
    ogs_pfcp_pdr_t *pdr = NULL;
    sgwu_sess_t *sess = NULL;
#if 0
    ogs_pfcp_subnet_t *subnet = NULL;
    ogs_pfcp_dev_t *dev = NULL;
#endif

    ogs_assert(fd != INVALID_SOCKET);

    pkbuf = ogs_pkbuf_alloc(packet_pool, OGS_MAX_SDU_LEN);
    ogs_pkbuf_put(pkbuf, OGS_MAX_SDU_LEN);

    size = ogs_recvfrom(fd, pkbuf->data, pkbuf->len, 0, &from);
    if (size <= 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "ogs_recv() failed");
        goto cleanup;
    }

    ogs_pkbuf_trim(pkbuf, size);

    ogs_assert(pkbuf);
    ogs_assert(pkbuf->len);

    gtp_h = (ogs_gtp_header_t *)pkbuf->data;
    if (gtp_h->version != OGS_GTP_VERSION_1) {
        ogs_error("[DROP] Invalid GTPU version [%d]", gtp_h->version);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }

    if (gtp_h->type == OGS_GTPU_MSGTYPE_ECHO_REQ) {
        ogs_pkbuf_t *echo_rsp;

        ogs_debug("[RECV] Echo Request from [%s]", OGS_ADDR(&from, buf));
        echo_rsp = ogs_gtp_handle_echo_req(pkbuf);
        if (echo_rsp) {
            ssize_t sent;

            /* Echo reply */
            ogs_debug("[SEND] Echo Response to [%s]", OGS_ADDR(&from, buf));

            sent = ogs_sendto(fd, echo_rsp->data, echo_rsp->len, 0, &from);
            if (sent < 0 || sent != echo_rsp->len) {
                ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                        "ogs_sendto() failed");
            }
            ogs_pkbuf_free(echo_rsp);
        }
        goto cleanup;
    }

    teid = be32toh(gtp_h->teid);

    if (gtp_h->type == OGS_GTPU_MSGTYPE_END_MARKER) {
        ogs_debug("[RECV] End Marker from [%s] : TEID[0x%x]",
                OGS_ADDR(&from, buf), teid);
        goto cleanup;
    }

    if (gtp_h->type == OGS_GTPU_MSGTYPE_ERR_IND) {
        ogs_error("[RECV] Error Indication from [%s]", OGS_ADDR(&from, buf));
        goto cleanup;
    }

    if (gtp_h->type != OGS_GTPU_MSGTYPE_GPDU) {
        ogs_error("[DROP] Invalid GTPU Type [%d]", gtp_h->type);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }

    ogs_debug("[RECV] GPU-U from [%s] : TEID[0x%x]",
            OGS_ADDR(&from, buf), teid);

    qfi = 0;
    if (gtp_h->flags & OGS_GTPU_FLAGS_E) {
        /*
         * TS29.281
         * 5.2.1 General format of the GTP-U Extension Header
         * Figure 5.2.1-3: Definition of Extension Header Type
         *
         * Note 4 : For a GTP-PDU with several Extension Headers, the PDU
         *          Session Container should be the first Extension Header
         */
        ogs_gtp_extension_header_t *extension_header =
            (ogs_gtp_extension_header_t *)(pkbuf->data + OGS_GTPV1U_HEADER_LEN);
        ogs_assert(extension_header);
        if (extension_header->type ==
                OGS_GTP_EXTENSION_HEADER_TYPE_PDU_SESSION_CONTAINER) {
            if (extension_header->pdu_type ==
                OGS_GTP_EXTENSION_HEADER_PDU_TYPE_UL_PDU_SESSION_INFORMATION) {
                    ogs_debug("   QFI [0x%x]",
                            extension_header->qos_flow_identifier);
                    qfi = extension_header->qos_flow_identifier;
            }
        }
    }

    /* Remove GTP header and send packets to TUN interface */
    len = ogs_gtpu_header_len(pkbuf);
    if (len < 0) {
        ogs_error("[DROP] Cannot decode GTPU packet");
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }
    ogs_assert(ogs_pkbuf_pull(pkbuf, len));

    ip_h = (struct ip *)pkbuf->data;
    ogs_assert(ip_h);

    pdr = ogs_pfcp_pdr_find_by_teid_and_qfi(teid, qfi);
    if (!pdr) {
        ogs_warn("[DROP] Cannot find PDR : UPF-N3-TEID[0x%x] QFI[%d]",
                teid, qfi);
        goto cleanup;
    }
    ogs_assert(pdr->sess);
    ogs_fatal("odr = %d", pdr->id);
#if 0
    sess = SGWU_SESS(pdr->sess);
    ogs_assert(sess);

    if (ip_h->ip_v == 4 && sess->ipv4)
        subnet = sess->ipv4->subnet;
    else if (ip_h->ip_v == 6 && sess->ipv6)
        subnet = sess->ipv6->subnet;

    if (!subnet) {
        ogs_error("[DROP] Cannot find subnet V:%d, IPv4:%p, IPv6:%p",
                ip_h->ip_v, sess->ipv4, sess->ipv6);
        ogs_log_hexdump(OGS_LOG_ERROR, pkbuf->data, pkbuf->len);
        goto cleanup;
    }

    /* Check IPv6 */
    if (ogs_config()->parameter.no_slaac == 0 && ip_h->ip_v == 6) {
        rv = upf_gtp_handle_slaac(sess, pkbuf);
        if (rv == UPF_GTP_HANDLED) {
            goto cleanup;
        }
        ogs_assert(rv == OGS_OK);
    }

    dev = subnet->dev;
    ogs_assert(dev);
    if (ogs_write(dev->fd, pkbuf->data, pkbuf->len) <= 0)
        ogs_error("ogs_write() failed");
#endif

cleanup:
    ogs_pkbuf_free(pkbuf);
}

int sgwu_gtp_open(void)
{
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;

    ogs_pkbuf_config_t config;
    memset(&config, 0, sizeof config);

    config.cluster_8192_pool = ogs_config()->pool.packet;

    packet_pool = ogs_pkbuf_pool_create(&config);

    ogs_list_for_each(&sgwu_self()->gtpu_list, node) {
        sock = ogs_gtp_server(node);
        ogs_assert(sock);

        if (sock->family == AF_INET)
            sgwu_self()->gtpu_sock = sock;
        else if (sock->family == AF_INET6)
            sgwu_self()->gtpu_sock6 = sock;

        node->poll = ogs_pollset_add(sgwu_self()->pollset,
                OGS_POLLIN, sock->fd, _gtpv1_u_recv_cb, sock);
    }

    ogs_assert(sgwu_self()->gtpu_sock || sgwu_self()->gtpu_sock6);

    return OGS_OK;
}

void sgwu_gtp_close(void)
{
    ogs_socknode_remove_all(&sgwu_self()->gtpu_list);

    ogs_pkbuf_pool_destroy(packet_pool);
}

#if 0
void sgwu_gtp_send_end_marker(sgwu_tunnel_t *s1u_tunnel)
{
    char buf[OGS_ADDRSTRLEN];
    int rv;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_gtp_header_t *h = NULL;

    ogs_assert(s1u_tunnel);
    ogs_assert(s1u_tunnel->gnode);
    ogs_assert(s1u_tunnel->gnode->sock);

    ogs_debug("[SGW] SEND End Marker to ENB[%s]: TEID[0x%x]",
        OGS_ADDR(&s1u_tunnel->gnode->addr, buf),
        s1u_tunnel->remote_teid);

    pkbuf = ogs_pkbuf_alloc(NULL,
            100 /* enough for END_MARKER; use smaller buffer */);
    ogs_pkbuf_put(pkbuf, 100);
    h = (ogs_gtp_header_t *)pkbuf->data;

    memset(h, 0, OGS_GTPV1U_HEADER_LEN);

    /*
     * Flags
     * 0x20 - Version : GTP release 99 version (1)
     * 0x10 - Protocol Type : GTP (1)
     */
    h->flags = 0x30;
    h->type = OGS_GTPU_MSGTYPE_END_MARKER;
    h->teid =  htonl(s1u_tunnel->remote_teid);
    
    rv = ogs_gtp_sendto(s1u_tunnel->gnode, pkbuf);
    ogs_expect(rv == OGS_OK);
    ogs_pkbuf_free(pkbuf);
}
#endif
