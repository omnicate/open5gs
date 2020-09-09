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
            ogs_app()->time.message.pfcp.no_heartbeat_duration);
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

void ogs_pfcp_up_handle_pdr(
        ogs_pfcp_pdr_t *pdr, ogs_pkbuf_t *recvbuf,
        ogs_pfcp_user_plane_report_t *report)
{
    ogs_pfcp_far_t *far = NULL;
    ogs_pkbuf_t *sendbuf = NULL;
    bool buffering;

    ogs_assert(recvbuf);
    ogs_assert(pdr);
    ogs_assert(report);

    far = pdr->far;
    ogs_assert(far);

    memset(report, 0, sizeof(*report));

    sendbuf = ogs_pkbuf_copy(recvbuf);
    ogs_assert(sendbuf);

    buffering = false;

    if (!far->gnode) {
        buffering = true;

    } else {
        if (far->apply_action & OGS_PFCP_APPLY_ACTION_FORW) {

            /* Forward packet */
            ogs_pfcp_send_g_pdu(pdr, sendbuf);

        } else if (far->apply_action & OGS_PFCP_APPLY_ACTION_BUFF) {

            buffering = true;

        } else {
            ogs_error("Not implemented");
            ogs_pkbuf_free(sendbuf);
        }
    }

    if (buffering == true) {

        if (far->num_of_buffered_packet == 0) {
            /* Only the first time a packet is buffered,
             * it reports downlink notifications. */
            report->type.downlink_data_report = 1;
        }

        if (far->num_of_buffered_packet < MAX_NUM_OF_PACKET_BUFFER) {
            far->buffered_packet[far->num_of_buffered_packet++] = sendbuf;
        }
    }
}

ogs_pfcp_pdr_t *ogs_pfcp_handle_create_pdr(ogs_pfcp_sess_t *sess,
        ogs_pfcp_tlv_create_pdr_t *message,
        uint8_t *cause_value, uint8_t *offending_ie_value)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_far_t *far = NULL;
    ogs_pfcp_qer_t *qer = NULL;
    int i, len;
    int rv;

    ogs_assert(sess);
    ogs_assert(message);

    if (message->presence == 0)
        return NULL;

    if (message->pdr_id.presence == 0) {
        ogs_error("No PDR-ID");
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
        *offending_ie_value = OGS_PFCP_PDR_ID_TYPE;
        return NULL;
    }

    pdr = ogs_pfcp_pdr_find_or_add(sess, message->pdr_id.u16);
    ogs_assert(pdr);

    if (message->precedence.presence) {
        ogs_pfcp_pdr_reorder_by_precedence(pdr, message->precedence.u32);
        pdr->precedence = message->precedence.u32;
    }

    if (message->pdi.presence == 0) {
        ogs_error("No PDI in PDR");
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
        *offending_ie_value = OGS_PFCP_PDI_TYPE;
        return NULL;
    }

    if (message->pdi.source_interface.presence == 0) {
        ogs_error("No Source Interface in PDI");
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
        *offending_ie_value = OGS_PFCP_SOURCE_INTERFACE_TYPE;
        return NULL;
    }

    pdr->src_if = message->pdi.source_interface.u8;

    ogs_pfcp_rule_remove_all(pdr);

    for (i = 0; i < OGS_MAX_NUM_OF_RULE; i++) {
        ogs_pfcp_sdf_filter_t sdf_filter_in_message;
        if (message->pdi.sdf_filter[i].presence == 0)
            break;

        len = ogs_pfcp_parse_sdf_filter(
                &sdf_filter_in_message, &message->pdi.sdf_filter[i]);
        ogs_assert(message->pdi.sdf_filter[i].len == len);
        if (sdf_filter_in_message.fd) {
            ogs_pfcp_rule_t *rule = NULL;
            char *flow_description = NULL;

            flow_description = ogs_malloc(
                    sdf_filter_in_message.flow_description_len+1);
            ogs_cpystrn(flow_description,
                    sdf_filter_in_message.flow_description,
                    sdf_filter_in_message.flow_description_len+1);

            rule = ogs_pfcp_rule_add(pdr);
            ogs_assert(rule);
            rv = ogs_ipfw_compile_rule(&rule->ipfw, flow_description);
            ogs_assert(rv == OGS_OK);

            ogs_free(flow_description);
        }
    }

    if (message->pdi.network_instance.presence) {
        char dnn[OGS_MAX_DNN_LEN];

        ogs_fqdn_parse(dnn,
            message->pdi.network_instance.data,
            message->pdi.network_instance.len);

        if (pdr->dnn)
            ogs_free(pdr->dnn);
        pdr->dnn = ogs_strdup(dnn);
    }

    if (message->pdi.local_f_teid.presence) {
        pdr->f_teid_len = message->pdi.local_f_teid.len;
        memcpy(&pdr->f_teid, message->pdi.local_f_teid.data, pdr->f_teid_len);
        pdr->f_teid.teid = be32toh(pdr->f_teid.teid);
    }

    if (message->pdi.qfi.presence) {
        pdr->qfi = message->pdi.qfi.u8;
    }

    if (message->outer_header_removal.presence) {
        pdr->outer_header_removal_len = message->outer_header_removal.len;
        memcpy(&pdr->outer_header_removal, message->outer_header_removal.data,
                pdr->outer_header_removal_len);
    }

    if (message->far_id.presence) {
        far = ogs_pfcp_far_find_or_add(sess, message->far_id.u32);
        ogs_assert(far);
        ogs_pfcp_pdr_associate_far(pdr, far);
    }

    if (message->qer_id.presence) {
        qer = ogs_pfcp_qer_find_or_add(sess, message->qer_id.u32);
        ogs_assert(qer);
        ogs_pfcp_pdr_associate_qer(pdr, qer);
    }

    if (message->far_id.presence) {
        far = ogs_pfcp_far_find_or_add(sess, message->far_id.u32);
        ogs_assert(far);
        ogs_pfcp_pdr_associate_far(pdr, far);
    }

    if (message->qer_id.presence) {
        qer = ogs_pfcp_qer_find_or_add(sess, message->qer_id.u32);
        ogs_assert(qer);
        ogs_pfcp_pdr_associate_qer(pdr, qer);
    }

    return pdr;
}

ogs_pfcp_pdr_t *ogs_pfcp_handle_update_pdr(ogs_pfcp_sess_t *sess,
        ogs_pfcp_tlv_update_pdr_t *message,
        uint8_t *cause_value, uint8_t *offending_ie_value)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    int i, len;
    int rv;

    ogs_assert(message);
    ogs_assert(sess);

    if (message->presence == 0)
        return NULL;

    if (message->pdr_id.presence == 0) {
        ogs_error("No PDR-ID");
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
        *offending_ie_value = OGS_PFCP_PDR_ID_TYPE;
        return NULL;
    }

    pdr = ogs_pfcp_pdr_find(sess, message->pdr_id.u16);
    if (!pdr) {
        ogs_error("Cannot find PDR-ID[%d] in PDR", message->pdr_id.u16);
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
        *offending_ie_value = OGS_PFCP_PDR_ID_TYPE;
        return NULL;
    }

    if (message->pdi.presence) {
        if (message->pdi.source_interface.presence == 0) {
            ogs_error("No Source Interface in PDI");
            *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            *offending_ie_value = OGS_PFCP_SOURCE_INTERFACE_TYPE;
            return NULL;
        }

        pdr->src_if = message->pdi.source_interface.u8;

        ogs_pfcp_rule_remove_all(pdr);

        for (i = 0; i < OGS_MAX_NUM_OF_RULE; i++) {
            ogs_pfcp_sdf_filter_t sdf_filter_in_message;

            if (message->pdi.sdf_filter[i].presence == 0)
                break;

            len = ogs_pfcp_parse_sdf_filter(
                    &sdf_filter_in_message, &message->pdi.sdf_filter[i]);
            ogs_assert(message->pdi.sdf_filter[i].len == len);
            if (sdf_filter_in_message.fd) {
                ogs_pfcp_rule_t *rule = NULL;
                char *flow_description = NULL;

                flow_description = ogs_malloc(
                        sdf_filter_in_message.flow_description_len+1);
                ogs_cpystrn(flow_description,
                        sdf_filter_in_message.flow_description,
                        sdf_filter_in_message.flow_description_len+1);

                rule = ogs_pfcp_rule_add(pdr);
                ogs_assert(rule);
                rv = ogs_ipfw_compile_rule(&rule->ipfw, flow_description);
                ogs_assert(rv == OGS_OK);

                ogs_free(flow_description);
            }

        }

        if (message->pdi.network_instance.presence) {
            char dnn[OGS_MAX_DNN_LEN];

            ogs_fqdn_parse(dnn,
                message->pdi.network_instance.data,
                message->pdi.network_instance.len);

            if (pdr->dnn)
                ogs_free(pdr->dnn);
            pdr->dnn = ogs_strdup(dnn);
        }

        if (message->pdi.local_f_teid.presence) {
            pdr->f_teid_len = message->pdi.local_f_teid.len;
            memcpy(&pdr->f_teid,
                    message->pdi.local_f_teid.data, pdr->f_teid_len);
            pdr->f_teid.teid = be32toh(pdr->f_teid.teid);
        }

        if (message->pdi.qfi.presence) {
            pdr->qfi = message->pdi.qfi.u8;
        }
    }

    return pdr;
}

bool ogs_pfcp_handle_remove_pdr(ogs_pfcp_sess_t *sess,
        ogs_pfcp_tlv_remove_pdr_t *message,
        uint8_t *cause_value, uint8_t *offending_ie_value)
{
    ogs_pfcp_pdr_t *pdr = NULL;

    ogs_assert(sess);
    ogs_assert(message);

    if (message->presence == 0)
        return false;

    if (message->pdr_id.presence == 0) {
        ogs_error("No PDR-ID");
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
        *offending_ie_value = OGS_PFCP_PDR_ID_TYPE;
        return false;
    }

    pdr = ogs_pfcp_pdr_find(sess, message->pdr_id.u16);
    if (!pdr) {
        ogs_error("Unknown PDR-ID[%d]", message->pdr_id.u16);
        *cause_value = OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;
        return false;
    }

    ogs_pfcp_pdr_remove(pdr);

    return true;
}

ogs_pfcp_far_t *ogs_pfcp_handle_create_far(ogs_pfcp_sess_t *sess,
        ogs_pfcp_tlv_create_far_t *message,
        uint8_t *cause_value, uint8_t *offending_ie_value)
{
    ogs_pfcp_far_t *far = NULL;

    ogs_assert(message);
    ogs_assert(sess);

    if (message->presence == 0)
        return NULL;

    if (message->far_id.presence == 0) {
        ogs_error("No FAR-ID");
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
        *offending_ie_value = OGS_PFCP_FAR_ID_TYPE;
        return NULL;
    }

    far = ogs_pfcp_far_find(sess, message->far_id.u32);
    if (!far) {
        ogs_error("Cannot find FAR-ID[%d] in PDR", message->far_id.u32);
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
        *offending_ie_value = OGS_PFCP_FAR_ID_TYPE;
        return NULL;
    }

    if (message->apply_action.presence == 0) {
        ogs_error("No Apply Action");
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
        *offending_ie_value = OGS_PFCP_APPLY_ACTION_TYPE;
        return NULL;
    }
    if (message->forwarding_parameters.
            destination_interface.presence == 0) {
        return far;
    }

    far->apply_action = message->apply_action.u8;
    far->dst_if = message->forwarding_parameters.destination_interface.u8;

    if (message->forwarding_parameters.outer_header_creation.presence) {
        ogs_pfcp_tlv_outer_header_creation_t *outer_header_creation =
            &message->forwarding_parameters.outer_header_creation;

        ogs_assert(outer_header_creation->data);
        ogs_assert(outer_header_creation->len);

        memcpy(&far->outer_header_creation,
                outer_header_creation->data, outer_header_creation->len);
        far->outer_header_creation.teid =
                be32toh(far->outer_header_creation.teid);
    }

    return far;
}

ogs_pfcp_far_t *ogs_pfcp_handle_update_far_flags(ogs_pfcp_sess_t *sess,
        ogs_pfcp_tlv_update_far_t *message,
        uint8_t *cause_value, uint8_t *offending_ie_value)
{
    ogs_pfcp_far_t *far = NULL;

    ogs_assert(message);
    ogs_assert(sess);

    if (message->presence == 0)
        return NULL;

    if (message->far_id.presence == 0) {
        ogs_error("No FAR-ID");
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
        *offending_ie_value = OGS_PFCP_FAR_ID_TYPE;
        return NULL;
    }

    far = ogs_pfcp_far_find(sess, message->far_id.u32);
    if (!far) {
        ogs_error("Cannot find FAR-ID[%d] in PDR", message->far_id.u32);
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
        *offending_ie_value = OGS_PFCP_FAR_ID_TYPE;
        return NULL;
    }

    if (message->update_forwarding_parameters.presence) {

        if (message->update_forwarding_parameters.pfcpsmreq_flags.presence) {
            far->smreq_flags.value =
                message->update_forwarding_parameters.pfcpsmreq_flags.u8;
        }
    }

    return far;
}

ogs_pfcp_far_t *ogs_pfcp_handle_update_far(ogs_pfcp_sess_t *sess,
        ogs_pfcp_tlv_update_far_t *message,
        uint8_t *cause_value, uint8_t *offending_ie_value)
{
    ogs_pfcp_far_t *far = NULL;

    ogs_assert(message);
    ogs_assert(sess);

    if (message->presence == 0)
        return NULL;

    if (message->far_id.presence == 0) {
        ogs_error("No FAR-ID");
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
        *offending_ie_value = OGS_PFCP_FAR_ID_TYPE;
        return NULL;
    }

    far = ogs_pfcp_far_find(sess, message->far_id.u32);
    if (!far) {
        ogs_error("Cannot find FAR-ID[%d] in PDR", message->far_id.u32);
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
        *offending_ie_value = OGS_PFCP_FAR_ID_TYPE;
        return NULL;
    }

    if (message->apply_action.presence)
        far->apply_action = message->apply_action.u8;

    if (message->update_forwarding_parameters.destination_interface.presence) {
        far->dst_if = message->update_forwarding_parameters.
            destination_interface.u8;
    }

    if (message->update_forwarding_parameters.presence) {
        if (message->update_forwarding_parameters.
                outer_header_creation.presence) {
            ogs_pfcp_tlv_outer_header_creation_t *outer_header_creation =
                &message->update_forwarding_parameters.outer_header_creation;

            ogs_assert(outer_header_creation->data);
            ogs_assert(outer_header_creation->len);

            memcpy(&far->outer_header_creation,
                    outer_header_creation->data, outer_header_creation->len);
            far->outer_header_creation.teid =
                    be32toh(far->outer_header_creation.teid);
        }
    }

    return far;
}

bool ogs_pfcp_handle_remove_far(ogs_pfcp_sess_t *sess,
        ogs_pfcp_tlv_remove_far_t *message,
        uint8_t *cause_value, uint8_t *offending_ie_value)
{
    ogs_pfcp_far_t *far = NULL;

    ogs_assert(sess);
    ogs_assert(message);

    if (message->presence == 0)
        return false;

    if (message->far_id.presence == 0) {
        ogs_error("No FAR-ID");
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
        *offending_ie_value = OGS_PFCP_FAR_ID_TYPE;
        return false;
    }

    far = ogs_pfcp_far_find(sess, message->far_id.u32);
    if (!far) {
        ogs_error("Unknown FAR-ID[%d]", message->far_id.u32);
        *cause_value = OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;
        return false;
    }

    ogs_pfcp_far_remove(far);

    return true;
}

ogs_pfcp_qer_t *ogs_pfcp_handle_create_qer(ogs_pfcp_sess_t *sess,
        ogs_pfcp_tlv_create_qer_t *message,
        uint8_t *cause_value, uint8_t *offending_ie_value)
{
    ogs_pfcp_qer_t *qer = NULL;

    ogs_assert(message);
    ogs_assert(sess);

    if (message->presence == 0)
        return NULL;

    if (message->qer_id.presence == 0) {
        ogs_error("No QER-ID");
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
        *offending_ie_value = OGS_PFCP_FAR_ID_TYPE;
        return NULL;
    }

    qer = ogs_pfcp_qer_find(sess, message->qer_id.u32);
    if (!qer) {
        ogs_error("Cannot find QER-ID[%d] in PDR", message->qer_id.u32);
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
        *offending_ie_value = OGS_PFCP_FAR_ID_TYPE;
        return NULL;
    }

    if (message->gate_status.presence == 0) {
        ogs_error("No Gate Status");
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
        *offending_ie_value = OGS_PFCP_APPLY_ACTION_TYPE;
        return NULL;
    }

    qer->gate_status.value = message->gate_status.u8;

    if (message->maximum_bitrate.presence)
        ogs_pfcp_parse_bitrate(&qer->mbr, &message->maximum_bitrate);
    if (message->guaranteed_bitrate.presence)
        ogs_pfcp_parse_bitrate(&qer->gbr, &message->guaranteed_bitrate);

    if (message->qos_flow_identifier.presence)
        qer->qfi = message->qos_flow_identifier.u8;

    return qer;
}

ogs_pfcp_qer_t *ogs_pfcp_handle_update_qer(ogs_pfcp_sess_t *sess,
        ogs_pfcp_tlv_update_qer_t *message,
        uint8_t *cause_value, uint8_t *offending_ie_value)
{
    ogs_pfcp_qer_t *qer = NULL;

    ogs_assert(message);
    ogs_assert(sess);

    if (message->presence == 0)
        return NULL;

    if (message->qer_id.presence == 0) {
        ogs_error("No QER-ID");
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
        *offending_ie_value = OGS_PFCP_FAR_ID_TYPE;
        return NULL;
    }

    qer = ogs_pfcp_qer_find(sess, message->qer_id.u32);
    if (!qer) {
        ogs_error("Cannot find QER-ID[%d] in PDR", message->qer_id.u32);
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
        *offending_ie_value = OGS_PFCP_FAR_ID_TYPE;
        return NULL;
    }

    if (message->maximum_bitrate.presence)
        ogs_pfcp_parse_bitrate(&qer->mbr, &message->maximum_bitrate);
    if (message->guaranteed_bitrate.presence)
        ogs_pfcp_parse_bitrate(&qer->gbr, &message->guaranteed_bitrate);

    return qer;
}

bool ogs_pfcp_handle_remove_qer(ogs_pfcp_sess_t *sess,
        ogs_pfcp_tlv_remove_qer_t *message,
        uint8_t *cause_value, uint8_t *offending_ie_value)
{
    ogs_pfcp_qer_t *qer = NULL;

    ogs_assert(sess);
    ogs_assert(message);

    if (message->presence == 0)
        return false;

    if (message->qer_id.presence == 0) {
        ogs_error("No QER-ID");
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
        *offending_ie_value = OGS_PFCP_QER_ID_TYPE;
        return false;
    }

    qer = ogs_pfcp_qer_find(sess, message->qer_id.u32);
    if (!qer) {
        ogs_error("Unknown QER-ID[%d]", message->qer_id.u32);
        *cause_value = OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND;
        return false;
    }

    ogs_pfcp_qer_remove(qer);

    return true;
}
