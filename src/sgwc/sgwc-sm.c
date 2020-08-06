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

#include "s11-handler.h"
#include "s5c-handler.h"

#include "gtp-path.h"
#include "pfcp-path.h"

static void sgwc_handle_echo_request(
        ogs_gtp_xact_t *xact, ogs_gtp_echo_request_t *req)
{
    ogs_assert(xact);
    ogs_assert(req);

    ogs_debug("[SGW] Receiving Echo Request");
    /* FIXME : Before implementing recovery counter correctly,
     *         I'll re-use the recovery value in request message */
    ogs_gtp_send_echo_response(xact, req->recovery.u8, 0);
}

static void sgwc_handle_echo_response(
        ogs_gtp_xact_t *s11_xact, ogs_gtp_echo_response_t *rsp)
{
    /* Not Implemented */
}


void sgwc_state_initial(ogs_fsm_t *s, sgwc_event_t *e)
{
    sgwc_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &sgwc_state_operational);
}

void sgwc_state_final(ogs_fsm_t *s, sgwc_event_t *e)
{
    sgwc_sm_debug(e);

    ogs_assert(s);
}

void sgwc_state_operational(ogs_fsm_t *s, sgwc_event_t *e)
{
    int rv;

    ogs_pkbuf_t *recvbuf = NULL;
    sgwc_ue_t *sgwc_ue = NULL;
    sgwc_sess_t *sess = NULL;
    sgwc_bearer_t *bearer = NULL;

    ogs_gtp_xact_t *gtp_xact = NULL;
    ogs_gtp_message_t gtp_message;
    ogs_gtp_node_t *gnode = NULL;

    ogs_pfcp_node_t *pfcp_node = NULL;
    ogs_pfcp_xact_t *pfcp_xact = NULL;
    ogs_pfcp_message_t pfcp_message;

    sgwc_sm_debug(e);

    ogs_assert(s);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        rv = sgwc_gtp_open();
        if (rv != OGS_OK) {
            ogs_error("Can't establish SGW path");
            break;
        }
        rv = sgwc_pfcp_open();
        if (rv != OGS_OK) {
            ogs_fatal("Can't establish N4-PFCP path");
            break;
        }
        break;

    case OGS_FSM_EXIT_SIG:
        sgwc_gtp_close();
        sgwc_pfcp_close();
        break;

    case SGWC_EVT_SXA_MESSAGE:
        ogs_assert(e);
        recvbuf = e->pkbuf;
        ogs_assert(recvbuf);
        pfcp_node = e->pfcp_node;
        ogs_assert(pfcp_node);
        ogs_assert(OGS_FSM_STATE(&pfcp_node->sm));

        if (ogs_pfcp_parse_msg(&pfcp_message, recvbuf) != OGS_OK) {
            ogs_error("ogs_pfcp_parse_msg() failed");
            ogs_pkbuf_free(recvbuf);
            break;
        }

        rv = ogs_pfcp_xact_receive(pfcp_node, &pfcp_message.h, &pfcp_xact);
        if (rv != OGS_OK) {
            ogs_pkbuf_free(recvbuf);
            break;
        }

        e->pfcp_message = &pfcp_message;
        e->pfcp_xact = pfcp_xact;

        e->gtp_message = NULL;
        if (pfcp_xact->gtpbuf) {
            ogs_pkbuf_push(pfcp_xact->gtpbuf, 12);
            rv = ogs_gtp_parse_msg(&gtp_message, pfcp_xact->gtpbuf);

            ogs_pkbuf_free(pfcp_xact->gtpbuf);
            e->gtp_message = &gtp_message;
        }

        ogs_fsm_dispatch(&pfcp_node->sm, e);
        if (OGS_FSM_CHECK(&pfcp_node->sm, sgwc_pfcp_state_exception)) {
            ogs_error("PFCP state machine exception");
        }

        ogs_pkbuf_free(recvbuf);
        break;

    case SGWC_EVT_SXA_TIMER:
    case SGWC_EVT_SXA_NO_HEARTBEAT:
        ogs_assert(e);
        pfcp_node = e->pfcp_node;
        ogs_assert(pfcp_node);
        ogs_assert(OGS_FSM_STATE(&pfcp_node->sm));

        ogs_fsm_dispatch(&pfcp_node->sm, e);
        break;

    case SGWC_EVT_S11_MESSAGE:
        ogs_assert(e);
        recvbuf = e->pkbuf;
        ogs_assert(recvbuf);

        if (ogs_gtp_parse_msg(&gtp_message, recvbuf) != OGS_OK) {
            ogs_error("ogs_gtp_parse_msg() failed");
            ogs_pkbuf_free(recvbuf);
            break;
        }

        if (gtp_message.h.teid_presence && gtp_message.h.teid != 0) {
            /* Cause is not "Context not found" */
            sgwc_ue = sgwc_ue_find_by_teid(gtp_message.h.teid);
        }

        if (sgwc_ue) {
            gnode = sgwc_ue->gnode;
            ogs_assert(gnode);
        } else {
            gnode = e->gnode;
            ogs_assert(gnode);
        }

        rv = ogs_gtp_xact_receive(gnode, &gtp_message.h, &gtp_xact);
        if (rv != OGS_OK) {
            ogs_pkbuf_free(recvbuf);
            break;
        }

        switch(gtp_message.h.type) {
        case OGS_GTP_ECHO_REQUEST_TYPE:
            sgwc_handle_echo_request(gtp_xact, &gtp_message.echo_request);
            break;
        case OGS_GTP_ECHO_RESPONSE_TYPE:
            sgwc_handle_echo_response(gtp_xact, &gtp_message.echo_response);
            break;
        case OGS_GTP_CREATE_SESSION_REQUEST_TYPE:
            if (gtp_message.h.teid == 0) {
                ogs_expect(!sgwc_ue);
                sgwc_ue = sgwc_ue_add_by_message(&gtp_message);
                if (sgwc_ue)
                    OGS_SETUP_GTP_NODE(sgwc_ue, gnode);
            }
            sgwc_s11_handle_create_session_request(
                    sgwc_ue, gtp_xact, recvbuf,
                    &gtp_message.create_session_request);
            break;
        case OGS_GTP_MODIFY_BEARER_REQUEST_TYPE:
            sgwc_s11_handle_modify_bearer_request(gtp_xact, sgwc_ue,
                    &gtp_message.modify_bearer_request);
            break;
        case OGS_GTP_DELETE_SESSION_REQUEST_TYPE:
            sgwc_s11_handle_delete_session_request(
                    gtp_xact, sgwc_ue, &gtp_message);
            break;
        case OGS_GTP_CREATE_BEARER_RESPONSE_TYPE:
            sgwc_s11_handle_create_bearer_response(
                    gtp_xact, sgwc_ue, &gtp_message);
            break;
        case OGS_GTP_UPDATE_BEARER_RESPONSE_TYPE:
            sgwc_s11_handle_update_bearer_response(
                    gtp_xact, sgwc_ue, &gtp_message);
            break;
        case OGS_GTP_DELETE_BEARER_RESPONSE_TYPE:
            sgwc_s11_handle_delete_bearer_response(
                    gtp_xact, sgwc_ue, &gtp_message);
            break;
        case OGS_GTP_RELEASE_ACCESS_BEARERS_REQUEST_TYPE:
            sgwc_s11_handle_release_access_bearers_request(gtp_xact, sgwc_ue,
                &gtp_message.release_access_bearers_request);
            break;
        case OGS_GTP_DOWNLINK_DATA_NOTIFICATION_ACKNOWLEDGE_TYPE:
            sgwc_s11_handle_downlink_data_notification_ack(gtp_xact, sgwc_ue,
                &gtp_message.downlink_data_notification_acknowledge);
            break;
        case OGS_GTP_CREATE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST_TYPE:
            sgwc_s11_handle_create_indirect_data_forwarding_tunnel_request(
                gtp_xact, sgwc_ue,
                &gtp_message.create_indirect_data_forwarding_tunnel_request);
            break;
        case OGS_GTP_DELETE_INDIRECT_DATA_FORWARDING_TUNNEL_REQUEST_TYPE:
            sgwc_s11_handle_delete_indirect_data_forwarding_tunnel_request(
                gtp_xact, sgwc_ue);
            break;
        case OGS_GTP_BEARER_RESOURCE_COMMAND_TYPE:
            sgwc_s11_handle_bearer_resource_command(
                    gtp_xact, sgwc_ue, &gtp_message);
            break;
        default:
            ogs_warn("Not implemented(type:%d)", gtp_message.h.type);
            break;
        }
        ogs_pkbuf_free(recvbuf);
        break;

    case SGWC_EVT_S5C_MESSAGE:
        ogs_assert(e);
        recvbuf = e->pkbuf;
        ogs_assert(recvbuf);

        if (ogs_gtp_parse_msg(&gtp_message, recvbuf) != OGS_OK) {
            ogs_error("ogs_gtp_parse_msg() failed");
            ogs_pkbuf_free(recvbuf);
            break;
        }

        if (gtp_message.h.teid_presence && gtp_message.h.teid != 0) {
            sess = sgwc_sess_find_by_teid(gtp_message.h.teid);
        }

        if (sess) {
            gnode = sess->gnode;
            ogs_assert(gnode);
        } else {
            gnode = e->gnode;
            ogs_assert(gnode);
        }

        rv = ogs_gtp_xact_receive(gnode, &gtp_message.h, &gtp_xact);
        if (rv != OGS_OK) {
            ogs_pkbuf_free(recvbuf);
            break;
        }

        switch(gtp_message.h.type) {
        case OGS_GTP_ECHO_REQUEST_TYPE:
            sgwc_handle_echo_request(gtp_xact, &gtp_message.echo_request);
            break;
        case OGS_GTP_ECHO_RESPONSE_TYPE:
            sgwc_handle_echo_response(gtp_xact, &gtp_message.echo_response);
            break;
        case OGS_GTP_CREATE_SESSION_RESPONSE_TYPE:
            sgwc_s5c_handle_create_session_response(gtp_xact, sess,
                    &gtp_message);
            break;
        case OGS_GTP_DELETE_SESSION_RESPONSE_TYPE:
            sgwc_s5c_handle_delete_session_response(gtp_xact, sess,
                    &gtp_message);
            break;
        case OGS_GTP_CREATE_BEARER_REQUEST_TYPE:
            sgwc_s5c_handle_create_bearer_request(gtp_xact, sess,
                    &gtp_message);
            break;
        case OGS_GTP_UPDATE_BEARER_REQUEST_TYPE:
            sgwc_s5c_handle_update_bearer_request(gtp_xact, sess,
                    &gtp_message);
            break;
        case OGS_GTP_DELETE_BEARER_REQUEST_TYPE:
            sgwc_s5c_handle_delete_bearer_request(gtp_xact, sess,
                    &gtp_message);
            break;
        case OGS_GTP_BEARER_RESOURCE_FAILURE_INDICATION_TYPE:
            sgwc_s5c_handle_bearer_resource_failure_indication(gtp_xact, sess,
                    &gtp_message);
            break;
        default:
            ogs_warn("Not implmeneted(type:%d)", gtp_message.h.type);
            break;
        }
        ogs_pkbuf_free(recvbuf);
        break;
    case SGWC_EVT_LO_DLDATA_NOTI:
        ogs_assert(e);

        bearer = e->bearer;
        ogs_assert(bearer);

        sgwc_s11_handle_lo_dldata_notification(bearer);

        break;
    default:
        ogs_error("No handler for event %s", sgwc_event_get_name(e));
        break;
    }
}
