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

#include "pfcp-path.h"
#include "gtp-path.h"
#include "sxa-handler.h"

void sgwu_sxa_handle_association_setup_request(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_association_setup_request_t *req)
{
    ogs_assert(xact);
    sgwu_pfcp_send_association_setup_response(
            xact, OGS_PFCP_CAUSE_REQUEST_ACCEPTED);
}

void sgwu_sxa_handle_association_setup_response(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_association_setup_response_t *rsp)
{
    ogs_assert(xact);
    ogs_pfcp_xact_commit(xact);
}

void sgwu_sxa_handle_heartbeat_request(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_heartbeat_request_t *req)
{
    ogs_assert(xact);
    ogs_pfcp_send_heartbeat_response(xact);
}

void sgwu_sxa_handle_heartbeat_response(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_heartbeat_response_t *rsp)
{
    ogs_assert(xact);
    ogs_pfcp_xact_commit(xact);

    ogs_timer_start(node->t_no_heartbeat,
            ogs_config()->time.message.pfcp.no_heartbeat_duration);
}

static void setup_gtp_node(ogs_pfcp_far_t *far,
    ogs_pfcp_tlv_outer_header_creation_t *outer_header_creation)
{
    int rv;
    ogs_ip_t ip;
    ogs_gtp_node_t *gnode = NULL;

    ogs_assert(far);
    ogs_assert(outer_header_creation);
    ogs_assert(outer_header_creation->presence);

    memcpy(&far->outer_header_creation,
            outer_header_creation->data, outer_header_creation->len);
    far->outer_header_creation.teid = be32toh(far->outer_header_creation.teid);

    rv = ogs_pfcp_outer_header_creation_to_ip(&far->outer_header_creation, &ip);
    ogs_assert(rv == OGS_OK);

    gnode = ogs_gtp_node_find_by_ip(&sgwu_self()->gnb_n3_list, &ip);
    if (!gnode) {
        gnode = ogs_gtp_node_add_by_ip(
            &sgwu_self()->gnb_n3_list, &ip, sgwu_self()->gtpu_port,
            ogs_config()->parameter.no_ipv4,
            ogs_config()->parameter.no_ipv6,
            ogs_config()->parameter.prefer_ipv4);
        ogs_assert(gnode);

        rv = ogs_gtp_connect(
                sgwu_self()->gtpu_sock, sgwu_self()->gtpu_sock6, gnode);
        ogs_assert(rv == OGS_OK);
    }
    OGS_SETUP_GTP_NODE(far, gnode);
}

static ogs_pfcp_pdr_t *handle_create_pdr(ogs_pfcp_sess_t *sess,
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

    /* APN(Network Instance) and UE IP Address
     * has already been processed in sgwu_sess_add() */

    if (pdr->src_if == OGS_PFCP_INTERFACE_CORE) {  /* Downlink */

        /* Nothing */

    } else if (pdr->src_if == OGS_PFCP_INTERFACE_ACCESS) { /* Uplink */
        if (message->pdi.local_f_teid.presence == 0) {
            ogs_error("No F-TEID in PDI");
            *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            *offending_ie_value = OGS_PFCP_F_TEID_TYPE;
            return NULL;
        }

        if (message->outer_header_removal.presence == 0) {
            ogs_error("No Outer Header Removal in PDI");
            *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_MISSING;
            *offending_ie_value = OGS_PFCP_OUTER_HEADER_REMOVAL_TYPE;
            return NULL;
        }

        pdr->f_teid_len = message->pdi.local_f_teid.len;
        memcpy(&pdr->f_teid, message->pdi.local_f_teid.data, pdr->f_teid_len);
        pdr->f_teid.teid = be32toh(pdr->f_teid.teid);

        memcpy(&pdr->outer_header_removal,
                message->outer_header_removal.data,
                message->outer_header_removal.len);
    } else {
        ogs_error("Invalid Source Interface[%d] in PDR", pdr->src_if);
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
        *offending_ie_value = OGS_PFCP_SOURCE_INTERFACE_TYPE;
        return NULL;
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

static bool handle_remove_pdr(ogs_pfcp_sess_t *sess,
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

static ogs_pfcp_far_t *handle_create_far(ogs_pfcp_sess_t *sess,
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

    if (far->dst_if == OGS_PFCP_INTERFACE_ACCESS) { /* Downlink */
        if (message->forwarding_parameters.outer_header_creation.presence) {
            setup_gtp_node(far,
                    &message->forwarding_parameters.outer_header_creation);
        }

    } else if (far->dst_if == OGS_PFCP_INTERFACE_CORE) {  /* Uplink */

        /* Nothing */

    } else {
        ogs_error("Invalid Destination Interface[%d] in FAR", far->dst_if);
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
        *offending_ie_value = OGS_PFCP_DESTINATION_INTERFACE_TYPE;
        return NULL;
    }

    return far;
}

static ogs_pfcp_far_t *handle_update_far(ogs_pfcp_sess_t *sess,
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

    if (message->update_forwarding_parameters.
            destination_interface.presence == 0)
        far->dst_if = message->update_forwarding_parameters.
            destination_interface.u8;

    if (far->dst_if == OGS_PFCP_INTERFACE_ACCESS) { /* Downlink */
        if (message->update_forwarding_parameters.
                outer_header_creation.presence) {
            setup_gtp_node(far,
                &message->update_forwarding_parameters.outer_header_creation);
        }

    } else if (far->dst_if == OGS_PFCP_INTERFACE_CORE) {  /* Uplink */

        /* Nothing */

    } else {
        ogs_error("Invalid Destination Interface[%d] in FAR", far->dst_if);
        *cause_value = OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT;
        *offending_ie_value = OGS_PFCP_DESTINATION_INTERFACE_TYPE;
        return NULL;
    }

    return far;
}

static bool handle_remove_far(ogs_pfcp_sess_t *sess,
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

static ogs_pfcp_qer_t *handle_create_qer(ogs_pfcp_sess_t *sess,
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

static ogs_pfcp_qer_t *handle_update_qer(ogs_pfcp_sess_t *sess,
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

static bool handle_remove_qer(ogs_pfcp_sess_t *sess,
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

void sgwu_sxa_handle_session_establishment_request(
        sgwu_sess_t *sess, ogs_pfcp_xact_t *xact, 
        ogs_pfcp_session_establishment_request_t *req)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_pdr_t *created_pdr[OGS_MAX_NUM_OF_PDR];
    int num_of_created_pdr = 0;
    uint8_t cause_value = 0;
    uint8_t offending_ie_value = 0;
    int i;

    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("Session Establishment Request");

    cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_error("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, 0);
        return;
    }

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        created_pdr[i] = handle_create_pdr(&sess->pfcp,
                &req->create_pdr[i], &cause_value, &offending_ie_value);
        if (created_pdr[i] == NULL)
            break;
    }
    num_of_created_pdr = i;
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        if (handle_create_far(&sess->pfcp, &req->create_far[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++) {
        if (handle_create_qer(&sess->pfcp, &req->create_qer[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /* Setup UPF-N3-TEID & QFI Hash */
    for (i = 0; i < num_of_created_pdr; i++) {
        pdr = created_pdr[i];
        ogs_assert(pdr);

        if (pdr->src_if == OGS_PFCP_INTERFACE_ACCESS) { /* Uplink */
            if (pdr->f_teid_len)
                ogs_pfcp_pdr_hash_set(pdr);
        }
    }

    /* Send Buffered Packet to gNB/SGW */
#if 0
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE) { /* Downlink */
            sgwu_gtp_send_buffered_packet(pdr);
        }
    }
#endif

    sgwu_pfcp_send_session_establishment_response(
            xact, sess, created_pdr, num_of_created_pdr);
    return;

cleanup:
    ogs_pfcp_sess_clear(&sess->pfcp);
    ogs_pfcp_send_error_message(xact, sess ? sess->sgwu_sxa_seid : 0,
            OGS_PFCP_SESSION_ESTABLISHMENT_RESPONSE_TYPE,
            cause_value, offending_ie_value);
}

void sgwu_sxa_handle_session_modification_request(
        sgwu_sess_t *sess, ogs_pfcp_xact_t *xact, 
        ogs_pfcp_session_modification_request_t *req)
{
    ogs_pfcp_pdr_t *pdr = NULL;
    ogs_pfcp_pdr_t *created_pdr[OGS_MAX_NUM_OF_PDR];
    int num_of_created_pdr = 0;
    uint8_t cause_value = 0;
    uint8_t offending_ie_value = 0;
    int i;

    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("Session Modification Request");

    cause_value = OGS_PFCP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_error("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                OGS_PFCP_SESSION_MODIFICATION_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, 0);
        return;
    }

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        created_pdr[i] = handle_create_pdr(&sess->pfcp,
                &req->create_pdr[i], &cause_value, &offending_ie_value);
        if (created_pdr[i] == NULL)
            break;
    }
    num_of_created_pdr = i;
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_PDR; i++) {
        if (handle_remove_pdr(&sess->pfcp, &req->remove_pdr[i],
                &cause_value, &offending_ie_value) == false)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        if (handle_create_far(&sess->pfcp, &req->create_far[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        if (handle_update_far(&sess->pfcp, &req->update_far[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_FAR; i++) {
        if (handle_remove_far(&sess->pfcp, &req->remove_far[i],
                &cause_value, &offending_ie_value) == false)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++) {
        if (handle_create_qer(&sess->pfcp, &req->create_qer[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++) {
        if (handle_update_qer(&sess->pfcp, &req->update_qer[i],
                    &cause_value, &offending_ie_value) == NULL)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    for (i = 0; i < OGS_MAX_NUM_OF_QER; i++) {
        if (handle_remove_qer(&sess->pfcp, &req->remove_qer[i],
                &cause_value, &offending_ie_value) == false)
            break;
    }
    if (cause_value != OGS_PFCP_CAUSE_REQUEST_ACCEPTED)
        goto cleanup;

    /* Setup UPF-N3-TEID & QFI Hash */
    for (i = 0; i < num_of_created_pdr; i++) {
        pdr = created_pdr[i];
        ogs_assert(pdr);

        if (pdr->src_if == OGS_PFCP_INTERFACE_ACCESS) { /* Uplink */
            if (pdr->f_teid_len)
                ogs_pfcp_pdr_hash_set(pdr);
        }
    }

    /* Send Buffered Packet to gNB/SGW */
#if 0
    ogs_list_for_each(&sess->pfcp.pdr_list, pdr) {
        if (pdr->src_if == OGS_PFCP_INTERFACE_CORE) { /* Downlink */
            sgwu_gtp_send_buffered_packet(pdr);
        }
    }
#endif

    sgwu_pfcp_send_session_modification_response(
            xact, sess, created_pdr, num_of_created_pdr);
    return;

cleanup:
    ogs_pfcp_sess_clear(&sess->pfcp);
    ogs_pfcp_send_error_message(xact, sess ? sess->sgwu_sxa_seid : 0,
            OGS_PFCP_SESSION_MODIFICATION_RESPONSE_TYPE,
            cause_value, offending_ie_value);
}

void sgwu_sxa_handle_session_deletion_request(
        sgwu_sess_t *sess, ogs_pfcp_xact_t *xact,
        ogs_pfcp_session_deletion_request_t *req)
{
    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("Session Deletion Request");

    if (!sess) {
        ogs_error("No Context");
        ogs_pfcp_send_error_message(xact, 0,
                OGS_PFCP_SESSION_DELETION_RESPONSE_TYPE,
                OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND, 0);
        return;
    }

    ogs_assert(sess);

    sgwu_pfcp_send_session_deletion_response(xact, sess);

    sgwu_sess_remove(sess);
}
