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

static struct {
    ogs_pfcp_f_teid_t f_teid;
    char dnn[OGS_MAX_DNN_LEN];
    char *sdf_filter[OGS_MAX_NUM_OF_RULE];
} pdrbuf[OGS_MAX_NUM_OF_PDR];

void ogs_pfcp_pdrbuf_init(void)
{
    memset(pdrbuf, 0, sizeof(pdrbuf));
}

void ogs_pfcp_pdrbuf_clear(void)
{
    int i, j;
    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        for (j = 0; j < OGS_MAX_NUM_OF_RULE; j++) {
            if (pdrbuf[i].sdf_filter[j])
                ogs_free(pdrbuf[i].sdf_filter[j]);
        }
    }
}

void ogs_pfcp_build_create_pdr(
    ogs_pfcp_tlv_create_pdr_t *message, int i, ogs_pfcp_pdr_t *pdr)
{
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_sess_t *pfcp_sess = NULL;
    int j = 0;
    int len = 0;

    ogs_assert(message);

    ogs_assert(pdr);
    pfcp_sess = pdr->sess;
    ogs_assert(pfcp_sess);

    far = pdr->far;
    ogs_assert(far);

    message->presence = 1;
    message->pdr_id.presence = 1;
    message->pdr_id.u16 = pdr->id;

    if (pdr->precedence) { /* No precedence in Sxa */
        message->precedence.presence = 1;
        message->precedence.u32 = pdr->precedence;
    }

    message->pdi.presence = 1;
    message->pdi.source_interface.presence = 1;
    message->pdi.source_interface.u8 = pdr->src_if;

    if (pdr->apn) {
        message->pdi.network_instance.presence = 1;
        message->pdi.network_instance.len = ogs_fqdn_build(
            pdrbuf[i].dnn, pdr->apn, strlen(pdr->apn));
        message->pdi.network_instance.data = pdrbuf[i].dnn;
    }

    for (j = 0; j < pdr->num_of_flow; j++) {
        ogs_pfcp_sdf_filter_t pfcp_sdf_filter[OGS_MAX_NUM_OF_RULE];
        pfcp_sdf_filter[j].fd = 1;
        pfcp_sdf_filter[j].flow_description_len =
                strlen(pdr->flow_description[j]);
        pfcp_sdf_filter[j].flow_description = pdr->flow_description[j];
        len = sizeof(ogs_pfcp_sdf_filter_t) +
                pfcp_sdf_filter[j].flow_description_len;

        message->pdi.sdf_filter[j].presence = 1;
        pdrbuf[i].sdf_filter[j] = ogs_calloc(1, len);
        ogs_pfcp_build_sdf_filter(&message->pdi.sdf_filter[j],
                &pfcp_sdf_filter[j], pdrbuf[i].sdf_filter[j], len);
    }

    if (pdr->ue_ip_addr_len) {
        message->pdi.ue_ip_address.presence = 1;
        message->pdi.ue_ip_address.data = &pdr->ue_ip_addr;
        message->pdi.ue_ip_address.len = pdr->ue_ip_addr_len;
    }

    if (pdr->f_teid_len) {
        memcpy(&pdrbuf[i].f_teid, &pdr->f_teid, pdr->f_teid_len);
        pdrbuf[i].f_teid.teid = htobe32(pdr->f_teid.teid);

        message->pdi.local_f_teid.presence = 1;
        message->pdi.local_f_teid.data = &pdrbuf[i].f_teid;
        message->pdi.local_f_teid.len = pdr->f_teid_len;
    }

    if (pdr->outer_header_removal_len) {
        message->outer_header_removal.presence = 1;
        message->outer_header_removal.data = &pdr->outer_header_removal;
        message->outer_header_removal.len = pdr->outer_header_removal_len;
    }

    if (pdr->far) {
        message->far_id.presence = 1;
        message->far_id.u32 = pdr->far->id;
    }

    if (pdr->urr) {
        message->urr_id.presence = 1;
        message->urr_id.u32 = pdr->urr->id;
    }

    if (pdr->qer) {
        message->qer_id.presence = 1;
        message->qer_id.u32 = pdr->qer->id;
    }
}

static struct {
    ogs_pfcp_outer_header_creation_t outer_header_creation;
} farbuf[OGS_MAX_NUM_OF_FAR];

void ogs_pfcp_build_create_far(
    ogs_pfcp_tlv_create_far_t *message, int i, ogs_pfcp_far_t *far)
{
    ogs_pfcp_sess_t *pfcp_sess = NULL;

    ogs_assert(message);
    ogs_assert(far);
    pfcp_sess = far->sess;
    ogs_assert(pfcp_sess);

    message->presence = 1;
    message->far_id.presence = 1;
    message->far_id.u32 = far->id;

    message->apply_action.presence = 1;
    message->apply_action.u8 = far->apply_action;

    message->forwarding_parameters.presence = 1;
    message->forwarding_parameters.destination_interface.presence = 1;
    message->forwarding_parameters.destination_interface.u8 =
        far->dst_if;

    if (far->outer_header_creation_len) {
        memcpy(&farbuf[i].outer_header_creation,
            &far->outer_header_creation, far->outer_header_creation_len);
        farbuf[i].outer_header_creation.teid =
                htobe32(far->outer_header_creation.teid);

        message->forwarding_parameters.outer_header_creation.presence = 1;
        message->forwarding_parameters.outer_header_creation.data =
                &farbuf[i].outer_header_creation;
        message->forwarding_parameters.outer_header_creation.len =
                far->outer_header_creation_len;
    }
}

void ogs_pfcp_build_create_urr(
    ogs_pfcp_tlv_create_urr_t *message, int i, ogs_pfcp_urr_t *urr)
{
    ogs_assert(message);
    ogs_assert(urr);

    message->presence = 1;
    message->urr_id.presence = 1;
    message->urr_id.u32 = urr->id;
}

static struct {
    char mbr[OGS_PFCP_BITRATE_LEN];
    char gbr[OGS_PFCP_BITRATE_LEN];
} create_qer_buf[OGS_MAX_NUM_OF_QER], update_qer_buf[OGS_MAX_NUM_OF_QER];

void ogs_pfcp_build_create_qer(
    ogs_pfcp_tlv_create_qer_t *message, int i, ogs_pfcp_qer_t *qer)
{
    ogs_assert(message);
    ogs_assert(qer);

    message->presence = 1;
    message->qer_id.presence = 1;
    message->qer_id.u32 = qer->id;

    message->gate_status.presence = 1;
    message->gate_status.u8 = qer->gate_status.value;

    if (qer->mbr.uplink || qer->mbr.downlink) {
        message->maximum_bitrate.presence = 1;
        ogs_pfcp_build_bitrate(
                &message->maximum_bitrate,
                &qer->mbr, create_qer_buf[i].mbr, OGS_PFCP_BITRATE_LEN);
    }
    if (qer->gbr.uplink || qer->gbr.downlink) {
        message->guaranteed_bitrate.presence = 1;
        ogs_pfcp_build_bitrate(
                &message->guaranteed_bitrate,
                &qer->gbr, create_qer_buf[i].gbr, OGS_PFCP_BITRATE_LEN);
    }

    if (qer->qfi) {
        message->qos_flow_identifier.presence = 1;
        message->qos_flow_identifier.u8 = qer->qfi;
    }
}

void ogs_pfcp_build_update_qer(
    ogs_pfcp_tlv_update_qer_t *message, int i, ogs_pfcp_qer_t *qer)
{
    ogs_assert(message);
    ogs_assert(qer);

    message->presence = 1;
    message->qer_id.presence = 1;
    message->qer_id.u32 = qer->id;

    if (qer->mbr.uplink || qer->mbr.downlink) {
        message->maximum_bitrate.presence = 1;
        ogs_pfcp_build_bitrate(
                &message->maximum_bitrate,
                &qer->mbr, update_qer_buf[i].mbr, OGS_PFCP_BITRATE_LEN);
    }
    if (qer->gbr.uplink || qer->gbr.downlink) {
        message->guaranteed_bitrate.presence = 1;
        ogs_pfcp_build_bitrate(
                &message->guaranteed_bitrate,
                &qer->gbr, update_qer_buf[i].gbr, OGS_PFCP_BITRATE_LEN);
    }
}

void ogs_pfcp_build_update_dl_far_deactivate(
        ogs_pfcp_tlv_update_far_t *message, int i, ogs_pfcp_far_t *far)
{
    ogs_assert(message);
    ogs_assert(far);

    if (far->dst_if == OGS_PFCP_INTERFACE_ACCESS) {
        message->presence = 1;
        message->far_id.presence = 1;
        message->far_id.u32 = far->id;

        far->apply_action =
            OGS_PFCP_APPLY_ACTION_BUFF | OGS_PFCP_APPLY_ACTION_NOCP;
        message->apply_action.presence = 1;
        message->apply_action.u8 = far->apply_action;
    }
}

void ogs_pfcp_build_update_far_activate(
        ogs_pfcp_tlv_update_far_t *message, int i, ogs_pfcp_far_t *far)
{
    ogs_assert(message);
    ogs_assert(far);

    message->presence = 1;
    message->far_id.presence = 1;
    message->far_id.u32 = far->id;

    if (far->apply_action != OGS_PFCP_APPLY_ACTION_FORW) {
        far->apply_action = OGS_PFCP_APPLY_ACTION_FORW;

        message->apply_action.presence = 1;
        message->apply_action.u8 = far->apply_action;
    }

    if (far->outer_header_creation_len) {
        memcpy(&farbuf[i].outer_header_creation,
            &far->outer_header_creation, far->outer_header_creation_len);
        farbuf[i].outer_header_creation.teid =
                htobe32(far->outer_header_creation.teid);

        message->update_forwarding_parameters.presence = 1;
        message->update_forwarding_parameters.
            outer_header_creation.presence = 1;
        message->update_forwarding_parameters.
            outer_header_creation.data = &farbuf[i].outer_header_creation;
        message->update_forwarding_parameters.
            outer_header_creation.len = far->outer_header_creation_len;
    }
}
