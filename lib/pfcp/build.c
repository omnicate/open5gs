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

ogs_pkbuf_t *ogs_pfcp_build_heartbeat_request(uint8_t type)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_heartbeat_request_t *req = NULL;

    ogs_debug("Heartbeat Request");

    req = &pfcp_message.pfcp_heartbeat_request;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    req->recovery_time_stamp.presence = 1;
    req->recovery_time_stamp.u32 = ogs_pfcp_self()->pfcp_started;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}

ogs_pkbuf_t *ogs_pfcp_build_heartbeat_response(uint8_t type)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_heartbeat_response_t *rsp = NULL;

    ogs_debug("Heartbeat Response");

    rsp = &pfcp_message.pfcp_heartbeat_response;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    rsp->recovery_time_stamp.presence = 1;
    rsp->recovery_time_stamp.u32 = ogs_pfcp_self()->pfcp_started;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}

ogs_pkbuf_t *ogs_pfcp_cp_build_association_setup_request(uint8_t type)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_association_setup_request_t *req = NULL;

    ogs_pfcp_node_id_t node_id;
    int node_id_len = 0;

    ogs_debug("Association Setup Request");

    req = &pfcp_message.pfcp_association_setup_request;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    ogs_pfcp_sockaddr_to_node_id(
            ogs_pfcp_self()->pfcp_addr, ogs_pfcp_self()->pfcp_addr6,
            ogs_config()->parameter.prefer_ipv4,
            &node_id, &node_id_len);
    req->node_id.presence = 1;
    req->node_id.data = &node_id;
    req->node_id.len = node_id_len;

    req->recovery_time_stamp.presence = 1;
    req->recovery_time_stamp.u32 = ogs_pfcp_self()->pfcp_started;

    req->cp_function_features.presence = 1;
    req->cp_function_features.u8 = ogs_pfcp_self()->cp_function_features;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}

ogs_pkbuf_t *ogs_pfcp_cp_build_association_setup_response(uint8_t type,
        uint8_t cause)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_association_setup_response_t *rsp = NULL;

    ogs_pfcp_node_id_t node_id;
    int node_id_len = 0;

    ogs_debug("Association Setup Response");

    rsp = &pfcp_message.pfcp_association_setup_response;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    ogs_pfcp_sockaddr_to_node_id(
            ogs_pfcp_self()->pfcp_addr, ogs_pfcp_self()->pfcp_addr6,
            ogs_config()->parameter.prefer_ipv4,
            &node_id, &node_id_len);
    rsp->node_id.presence = 1;
    rsp->node_id.data = &node_id;
    rsp->node_id.len = node_id_len;

    rsp->cause.presence = 1;
    rsp->cause.u8 = cause;

    rsp->recovery_time_stamp.presence = 1;
    rsp->recovery_time_stamp.u32 = ogs_pfcp_self()->pfcp_started;

    rsp->cp_function_features.presence = 1;
    rsp->cp_function_features.u8 = ogs_pfcp_self()->cp_function_features;

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}

ogs_pkbuf_t *ogs_pfcp_up_build_association_setup_request(uint8_t type)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_association_setup_request_t *req = NULL;

    ogs_pfcp_node_id_t node_id;
    int node_id_len = 0;

    ogs_pfcp_gtpu_resource_t *resource = NULL;
    char infobuf[OGS_MAX_NUM_OF_GTPU_RESOURCE]
                [OGS_PFCP_MAX_USER_PLANE_IP_RESOURCE_INFO_LEN];
    int i = 0;

    ogs_debug("Association Setup Request");

    req = &pfcp_message.pfcp_association_setup_request;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    ogs_pfcp_sockaddr_to_node_id(
            ogs_pfcp_self()->pfcp_addr, ogs_pfcp_self()->pfcp_addr6,
            ogs_config()->parameter.prefer_ipv4,
            &node_id, &node_id_len);
    req->node_id.presence = 1;
    req->node_id.data = &node_id;
    req->node_id.len = node_id_len;

    req->recovery_time_stamp.presence = 1;
    req->recovery_time_stamp.u32 = ogs_pfcp_self()->pfcp_started;

    req->up_function_features.presence = 1;
    req->up_function_features.u16 =
        htobe16(ogs_pfcp_self()->up_function_features);

    i = 0;
    ogs_list_for_each(&ogs_pfcp_self()->gtpu_resource_list, resource) {
        ogs_assert(i < OGS_MAX_NUM_OF_GTPU_RESOURCE);
        ogs_pfcp_tlv_user_plane_ip_resource_information_t *message =
            &req->user_plane_ip_resource_information[i];
        ogs_assert(message);

        message->presence = 1;
        ogs_pfcp_build_user_plane_ip_resource_info(
            message, &resource->info, infobuf[i],
            OGS_PFCP_MAX_USER_PLANE_IP_RESOURCE_INFO_LEN);
        i++;
    }

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}

ogs_pkbuf_t *ogs_pfcp_up_build_association_setup_response(uint8_t type,
        uint8_t cause)
{
    ogs_pfcp_message_t pfcp_message;
    ogs_pfcp_association_setup_response_t *rsp = NULL;

    ogs_pfcp_node_id_t node_id;
    int node_id_len = 0;

    ogs_pfcp_gtpu_resource_t *resource = NULL;
    char infobuf[OGS_MAX_NUM_OF_GTPU_RESOURCE]
                [OGS_PFCP_MAX_USER_PLANE_IP_RESOURCE_INFO_LEN];
    int i = 0;

    ogs_debug("Association Setup Response");

    rsp = &pfcp_message.pfcp_association_setup_response;
    memset(&pfcp_message, 0, sizeof(ogs_pfcp_message_t));

    ogs_pfcp_sockaddr_to_node_id(
            ogs_pfcp_self()->pfcp_addr, ogs_pfcp_self()->pfcp_addr6,
            ogs_config()->parameter.prefer_ipv4,
            &node_id, &node_id_len);
    rsp->node_id.presence = 1;
    rsp->node_id.data = &node_id;
    rsp->node_id.len = node_id_len;

    rsp->cause.presence = 1;
    rsp->cause.u8 = cause;

    rsp->recovery_time_stamp.presence = 1;
    rsp->recovery_time_stamp.u32 = ogs_pfcp_self()->pfcp_started;

    rsp->up_function_features.presence = 1;
    rsp->up_function_features.u16 =
        htobe16(ogs_pfcp_self()->up_function_features);

    i = 0;
    ogs_list_for_each(&ogs_pfcp_self()->gtpu_resource_list, resource) {
        ogs_assert(i < OGS_MAX_NUM_OF_GTPU_RESOURCE);
        ogs_pfcp_tlv_user_plane_ip_resource_information_t *message =
            &rsp->user_plane_ip_resource_information[i];
        ogs_assert(message);

        message->presence = 1;
        ogs_pfcp_build_user_plane_ip_resource_info(
            message, &resource->info, infobuf[i],
            OGS_PFCP_MAX_USER_PLANE_IP_RESOURCE_INFO_LEN);
        i++;
    }

    pfcp_message.h.type = type;
    return ogs_pfcp_build_msg(&pfcp_message);
}
