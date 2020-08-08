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

#include "ogs-pfcp.h"

void ogs_pfcp_handle_heartbeat_request(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact, 
        ogs_pfcp_heartbeat_request_t *req)
{
    ogs_assert(xact);
    ogs_pfcp_send_heartbeat_response(xact);
}

void ogs_pfcp_handle_heartbeat_response(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact, 
        ogs_pfcp_heartbeat_response_t *rsp)
{
    ogs_assert(xact);
    ogs_pfcp_xact_commit(xact);

    ogs_timer_start(node->t_no_heartbeat,
            ogs_config()->time.message.pfcp.no_heartbeat_duration);
}

void ogs_pfcp_cp_handle_association_setup_request(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact, 
        ogs_pfcp_association_setup_request_t *req)
{
    int i;

    ogs_assert(xact);
    ogs_assert(node);
    ogs_assert(req);

    ogs_pfcp_cp_send_association_setup_response(
            xact, OGS_PFCP_CAUSE_REQUEST_ACCEPTED);

    ogs_pfcp_gtpu_resource_remove_all(&node->gtpu_resource_list);

    for (i = 0; i < OGS_MAX_NUM_OF_GTPU_RESOURCE; i++) {
        ogs_pfcp_tlv_user_plane_ip_resource_information_t *message =
            &req->user_plane_ip_resource_information[i];
        ogs_pfcp_user_plane_ip_resource_info_t info;

        if (message->presence == 0)
            break;

        ogs_pfcp_parse_user_plane_ip_resource_info(&info, message);
        ogs_pfcp_gtpu_resource_add(&node->gtpu_resource_list, &info);
    }
}

void ogs_pfcp_cp_handle_association_setup_response(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact, 
        ogs_pfcp_association_setup_response_t *rsp)
{
    int i;

    ogs_assert(xact);
    ogs_pfcp_xact_commit(xact);

    ogs_assert(node);
    ogs_assert(rsp);

    ogs_pfcp_gtpu_resource_remove_all(&node->gtpu_resource_list);

    for (i = 0; i < OGS_MAX_NUM_OF_GTPU_RESOURCE; i++) {
        ogs_pfcp_tlv_user_plane_ip_resource_information_t *message =
            &rsp->user_plane_ip_resource_information[i];
        ogs_pfcp_user_plane_ip_resource_info_t info;

        if (message->presence == 0)
            break;

        ogs_pfcp_parse_user_plane_ip_resource_info(&info, message);
        ogs_pfcp_gtpu_resource_add(&node->gtpu_resource_list, &info);
    }
}

void ogs_pfcp_up_handle_association_setup_request(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_association_setup_request_t *req)
{
    ogs_assert(xact);
    ogs_pfcp_up_send_association_setup_response(
            xact, OGS_PFCP_CAUSE_REQUEST_ACCEPTED);
}

void ogs_pfcp_up_handle_association_setup_response(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_association_setup_response_t *rsp)
{
    ogs_assert(xact);
    ogs_pfcp_xact_commit(xact);
}

int ogs_pfcp_up_handle_pdr(ogs_pfcp_pdr_t *pdr, ogs_pkbuf_t *recvbuf)
{
    ogs_pfcp_far_t *far = NULL;
    ogs_pkbuf_t *sendbuf = NULL;

    ogs_assert(recvbuf);
    ogs_assert(pdr);

    far = pdr->far;
    ogs_assert(far);

    sendbuf = ogs_pkbuf_copy(recvbuf);
    ogs_assert(sendbuf);
    if (!far->gnode) {
        /* Default apply action : buffering */
        if (far->num_of_buffered_packet < MAX_NUM_OF_PACKET_BUFFER) {
            far->buffered_packet[far->num_of_buffered_packet++] = sendbuf;
            return OGS_PFCP_UP_HANDLED;
        }
    } else {
        if (far->apply_action & OGS_PFCP_APPLY_ACTION_FORW) {
            ogs_pfcp_send_g_pdu(pdr, sendbuf);
        } else if (far->apply_action & OGS_PFCP_APPLY_ACTION_BUFF) {
            if (far->num_of_buffered_packet < MAX_NUM_OF_PACKET_BUFFER) {
                far->buffered_packet[far->num_of_buffered_packet++] = sendbuf;
                return OGS_PFCP_UP_HANDLED;
            }
        }
        return OGS_PFCP_UP_HANDLED;
    }

    ogs_pkbuf_free(sendbuf);
    return OGS_OK;
}
