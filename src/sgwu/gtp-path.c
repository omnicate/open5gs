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

#define SGWU_GTP_HANDLED     1

static ogs_pkbuf_pool_t *packet_pool = NULL;

static void sgwu_gtp_send_to_nf(ogs_pfcp_pdr_t *pdr, ogs_pkbuf_t *sendbuf);
static int sgwu_gtp_handle_pdr(ogs_pfcp_pdr_t *pdr, ogs_pkbuf_t *recvbuf);

static void _gtpv1_u_recv_cb(short when, ogs_socket_t fd, void *data)
{
    int len;
    ssize_t size;
    char buf[OGS_ADDRSTRLEN];

    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sockaddr_t from;

    ogs_gtp_header_t *gtp_h = NULL;
    struct ip *ip_h = NULL;

    uint32_t teid;
    uint8_t qfi;
    ogs_pfcp_pdr_t *pdr = NULL;

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
        ogs_warn("[DROP] Cannot find PDR : TEID[0x%x] QFI[%d]",
                teid, qfi);
        goto cleanup;
    }

    sgwu_gtp_handle_pdr(pdr, pkbuf);

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

void sgwu_gtp_send_buffered_packet(ogs_pfcp_pdr_t *pdr)
{
    ogs_pfcp_far_t *far = NULL;
    int i;

    ogs_assert(pdr);
    far = pdr->far;

    if (far && far->gnode) {
        if (far->apply_action & OGS_PFCP_APPLY_ACTION_FORW) {
            for (i = 0; i < far->num_of_buffered_packet; i++) {
                sgwu_gtp_send_to_nf(pdr, far->buffered_packet[i]);
            }
            far->num_of_buffered_packet = 0;
        }
    }
}

static void sgwu_gtp_send_to_nf(ogs_pfcp_pdr_t *pdr, ogs_pkbuf_t *sendbuf)
{
    char buf[OGS_ADDRSTRLEN];
    int rv;
    ogs_gtp_header_t *gtp_h = NULL;
    ogs_gtp_extension_header_t *ext_h = NULL;
    ogs_gtp_node_t *gnode = NULL;

    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_qer_t *qer = NULL;

    ogs_assert(pdr);

    far = pdr->far;
    if (!far) {
        ogs_error("No FAR");
        return;
    }

#if 0
    if (far->dst_if != OGS_PFCP_INTERFACE_ACCESS) {
        ogs_error("FAR is NOT Downlink");
        return;
    }
#endif

    gnode = far->gnode;
    ogs_assert(gnode);
    ogs_assert(gnode->sock);
    ogs_assert(sendbuf);

    qer = pdr->qer;

    /* Add GTP-U header */
    if (qer && qer->qfi) {
        ogs_assert(ogs_pkbuf_push(sendbuf, OGS_GTPV1U_5GC_HEADER_LEN));
        gtp_h = (ogs_gtp_header_t *)sendbuf->data;
        /* Bits    8  7  6  5  4  3  2  1
         *        +--+--+--+--+--+--+--+--+
         *        |version |PT| 1| E| S|PN|
         *        +--+--+--+--+--+--+--+--+
         *         0  0  1   1  0  1  0  0
         */
        gtp_h->flags = 0x34;
        gtp_h->type = OGS_GTPU_MSGTYPE_GPDU;
        gtp_h->length = htobe16(sendbuf->len - OGS_GTPV1U_HEADER_LEN);
        gtp_h->teid = htobe32(far->outer_header_creation.teid);

        ext_h = (ogs_gtp_extension_header_t *)(
                sendbuf->data + OGS_GTPV1U_HEADER_LEN);
        ext_h->type = OGS_GTP_EXTENSION_HEADER_TYPE_PDU_SESSION_CONTAINER;
        ext_h->len = 1;
        ext_h->pdu_type =
            OGS_GTP_EXTENSION_HEADER_PDU_TYPE_DL_PDU_SESSION_INFORMATION;
        ext_h->qos_flow_identifier = qer->qfi;
        ext_h->next_type =
            OGS_GTP_EXTENSION_HEADER_TYPE_NO_MORE_EXTENSION_HEADERS;
    } else {
        ogs_assert(ogs_pkbuf_push(sendbuf, OGS_GTPV1U_HEADER_LEN));
        gtp_h = (ogs_gtp_header_t *)sendbuf->data;
        /* Bits    8  7  6  5  4  3  2  1
         *        +--+--+--+--+--+--+--+--+
         *        |version |PT| 1| E| S|PN|
         *        +--+--+--+--+--+--+--+--+
         *         0  0  1   1  0  0  0  0
         */
        gtp_h->flags = 0x30;
        gtp_h->type = OGS_GTPU_MSGTYPE_GPDU;
        gtp_h->length = htobe16(sendbuf->len - OGS_GTPV1U_HEADER_LEN);
        gtp_h->teid = htobe32(far->outer_header_creation.teid);
    }

    /* Send to gNB */
    ogs_debug("SEND GPU-U to Peer[%s] : TEID[0x%x]",
        OGS_ADDR(&gnode->addr, buf), far->outer_header_creation.teid);
    rv = ogs_gtp_sendto(gnode, sendbuf);
    if (rv != OGS_OK)
        ogs_error("ogs_gtp_sendto() failed");

    ogs_pkbuf_free(sendbuf);
}

static int sgwu_gtp_handle_pdr(ogs_pfcp_pdr_t *pdr, ogs_pkbuf_t *recvbuf)
{
    ogs_pfcp_far_t *far = NULL;
    ogs_pkbuf_t *sendbuf = NULL;

    ogs_assert(recvbuf);
    ogs_assert(pdr);

#if 0
    if (pdr->src_if != OGS_PFCP_INTERFACE_CORE) {
        ogs_error("PDR is NOT Downlink");
        return OGS_ERROR;
    }
#endif

    far = pdr->far;
    ogs_assert(far);

    sendbuf = ogs_pkbuf_copy(recvbuf);
    ogs_assert(sendbuf);
    if (!far->gnode) {
        /* Default apply action : buffering */
        if (far->num_of_buffered_packet < MAX_NUM_OF_PACKET_BUFFER) {
            far->buffered_packet[far->num_of_buffered_packet++] = sendbuf;
            return SGWU_GTP_HANDLED;
        }
    } else {
        if (far->apply_action & OGS_PFCP_APPLY_ACTION_FORW) {
            sgwu_gtp_send_to_nf(pdr, sendbuf);
        } else if (far->apply_action & OGS_PFCP_APPLY_ACTION_BUFF) {
            if (far->num_of_buffered_packet < MAX_NUM_OF_PACKET_BUFFER) {
                far->buffered_packet[far->num_of_buffered_packet++] = sendbuf;
                return SGWU_GTP_HANDLED;
            }
        }
        return SGWU_GTP_HANDLED;
    }

    ogs_pkbuf_free(sendbuf);
    return OGS_OK;
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
