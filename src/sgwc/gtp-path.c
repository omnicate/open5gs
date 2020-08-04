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

static void _gtpv2_c_recv_cb(short when, ogs_socket_t fd, void *data)
{
    sgwc_event_t *e = NULL;
    int rv;
    ssize_t size;
    ogs_pkbuf_t *pkbuf = NULL;
    ogs_sockaddr_t from;
    ogs_gtp_node_t *gnode = NULL;

    ogs_assert(fd != INVALID_SOCKET);

    pkbuf = ogs_pkbuf_alloc(NULL, OGS_MAX_SDU_LEN);
    ogs_pkbuf_put(pkbuf, OGS_MAX_SDU_LEN);

    size = ogs_recvfrom(fd, pkbuf->data, pkbuf->len, 0, &from);
    if (size <= 0) {
        ogs_log_message(OGS_LOG_ERROR, ogs_socket_errno,
                "ogs_recvfrom() failed");
        ogs_pkbuf_free(pkbuf);
        return;
    }

    ogs_pkbuf_trim(pkbuf, size);

    /*
     * 5.5.2 in spec 29.274
     *
     * If a peer's TEID is not available, the TEID field still shall be
     * present in the header and its value shall be set to "0" in the
     * following messages:
     *
     * - Create Session Request message on S2a/S2b/S5/S8
     *
     * - Create Session Request message on S4/S11, if for a given UE,
     *   the SGSN/MME has not yet obtained the Control TEID of the SGW.
     *
     * - If a node receives a message and the TEID-C in the GTPv2 header of
     *   the received message is not known, it shall respond with
     *   "Context not found" Cause in the corresponding response message
     *   to the sender, the TEID used in the GTPv2-C header in the response
     *   message shall be then set to zero.
     *
     * - If a node receives a request message containing protocol error,
     *   e.g. Mandatory IE missing, which requires the receiver to reject
     *   the message as specified in clause 7.7, it shall reject
     *   the request message. For the response message, the node should
     *   look up the remote peer's TEID and accordingly set the GTPv2-C
     *   header TEID and the message cause code. As an implementation
     *   option, the node may not look up the remote peer's TEID and
     *   set the GTPv2-C header TEID to zero in the response message.
     *   However in this case, the cause code shall not be set to
     *   "Context not found".
     */
    gnode = ogs_gtp_node_find_by_addr(&sgwc_self()->pgw_s5c_list, &from);
    if (gnode) {
        e = sgwc_event_new(SGWC_EVT_S5C_MESSAGE);
        ogs_assert(e);
        e->gnode = gnode;
    } else {
        e = sgwc_event_new(SGWC_EVT_S11_MESSAGE);
        gnode = ogs_gtp_node_find_by_addr(&sgwc_self()->mme_s11_list, &from);
        if (!gnode) {
            gnode = ogs_gtp_node_add_by_addr(&sgwc_self()->mme_s11_list, &from);
            ogs_assert(gnode);
            gnode->sock = data;
        }
        ogs_assert(e);
        e->gnode = gnode;
    }

    e->pkbuf = pkbuf;

    rv = ogs_queue_push(sgwc_self()->queue, e);
    if (rv != OGS_OK) {
        ogs_error("ogs_queue_push() failed:%d", (int)rv);
        ogs_pkbuf_free(e->pkbuf);
        sgwc_event_free(e);
    }
}

int sgwc_gtp_open(void)
{
    ogs_socknode_t *node = NULL;
    ogs_sock_t *sock = NULL;

    ogs_pkbuf_config_t config;
    memset(&config, 0, sizeof config);

    config.cluster_8192_pool = ogs_config()->pool.packet;

    packet_pool = ogs_pkbuf_pool_create(&config);

    ogs_list_for_each(&sgwc_self()->gtpc_list, node) {
        sock = ogs_gtp_server(node);
        ogs_assert(sock);

        node->poll = ogs_pollset_add(sgwc_self()->pollset,
                OGS_POLLIN, sock->fd, _gtpv2_c_recv_cb, sock);
    }
    ogs_list_for_each(&sgwc_self()->gtpc_list6, node) {
        sock = ogs_gtp_server(node);
        ogs_assert(sock);

        node->poll = ogs_pollset_add(sgwc_self()->pollset,
                OGS_POLLIN, sock->fd, _gtpv2_c_recv_cb, sock);
    }

    sgwc_self()->gtpc_sock = ogs_socknode_sock_first(&sgwc_self()->gtpc_list);
    if (sgwc_self()->gtpc_sock)
        sgwc_self()->gtpc_addr = &sgwc_self()->gtpc_sock->local_addr;

    sgwc_self()->gtpc_sock6 = ogs_socknode_sock_first(&sgwc_self()->gtpc_list6);
    if (sgwc_self()->gtpc_sock6)
        sgwc_self()->gtpc_addr6 = &sgwc_self()->gtpc_sock6->local_addr;

    ogs_assert(sgwc_self()->gtpc_addr || sgwc_self()->gtpc_addr6);

    return OGS_OK;
}

void sgwc_gtp_close(void)
{
    ogs_socknode_remove_all(&sgwc_self()->gtpc_list);
    ogs_socknode_remove_all(&sgwc_self()->gtpc_list6);

    ogs_pkbuf_pool_destroy(packet_pool);
}

void sgwc_gtp_send_end_marker(sgwc_tunnel_t *s1u_tunnel)
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
