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
#if 0
#include "bearer-binding.h"
#endif

static uint8_t gtp_cause_from_pfcp(uint8_t pfcp_cause)
{
    switch (pfcp_cause) {
    case OGS_PFCP_CAUSE_REQUEST_ACCEPTED:
        return OGS_GTP_CAUSE_REQUEST_ACCEPTED;
    case OGS_PFCP_CAUSE_REQUEST_REJECTED:
        return OGS_GTP_CAUSE_REQUEST_REJECTED_REASON_NOT_SPECIFIED;
    case OGS_PFCP_CAUSE_SESSION_CONTEXT_NOT_FOUND:
        return OGS_GTP_CAUSE_CONTEXT_NOT_FOUND;
    case OGS_PFCP_CAUSE_MANDATORY_IE_MISSING:
        return OGS_GTP_CAUSE_MANDATORY_IE_MISSING;
    case OGS_PFCP_CAUSE_CONDITIONAL_IE_MISSING:
        return OGS_GTP_CAUSE_CONDITIONAL_IE_MISSING;
    case OGS_PFCP_CAUSE_INVALID_LENGTH:
        return OGS_GTP_CAUSE_INVALID_LENGTH;
    case OGS_PFCP_CAUSE_MANDATORY_IE_INCORRECT:
        return OGS_GTP_CAUSE_MANDATORY_IE_INCORRECT;
    case OGS_PFCP_CAUSE_INVALID_FORWARDING_POLICY:
    case OGS_PFCP_CAUSE_INVALID_F_TEID_ALLOCATION_OPTION:
        return OGS_GTP_CAUSE_INVALID_MESSAGE_FORMAT;
    case OGS_PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOCIATION:
        return OGS_GTP_CAUSE_REMOTE_PEER_NOT_RESPONDING;
    case OGS_PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE:
        return OGS_GTP_CAUSE_SEMANTIC_ERROR_IN_THE_TFT_OPERATION;
    case OGS_PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION:
        return OGS_GTP_CAUSE_GTP_C_ENTITY_CONGESTION;
    case OGS_PFCP_CAUSE_NO_RESOURCES_AVAILABLE:
        return OGS_GTP_CAUSE_NO_RESOURCES_AVAILABLE;
    case OGS_PFCP_CAUSE_SERVICE_NOT_SUPPORTED:
        return OGS_GTP_CAUSE_SERVICE_NOT_SUPPORTED;
    case OGS_PFCP_CAUSE_SYSTEM_FAILURE:
        return OGS_GTP_CAUSE_SYSTEM_FAILURE;
    default:
        return OGS_GTP_CAUSE_SYSTEM_FAILURE;
    }

    return OGS_GTP_CAUSE_SYSTEM_FAILURE;
}

static void timeout(ogs_gtp_xact_t *xact, void *data)
{
    sgwc_sess_t *sess = data;
    sgwc_ue_t *sgwc_ue = NULL;
    uint8_t type = 0;

    ogs_assert(xact);
    ogs_assert(sess);
    sgwc_ue = sess->sgwc_ue;
    ogs_assert(sgwc_ue);

    type = xact->seq[0].type;

    ogs_error("GTP Timeout : IMSI[%s] Message-Type[%d]",
            sgwc_ue->imsi_bcd, type);
}

void sgwc_sxa_handle_session_establishment_response(
        sgwc_sess_t *sess, ogs_pfcp_xact_t *pfcp_xact,
        ogs_gtp_message_t *gtp_message,
        ogs_pfcp_session_establishment_response_t *pfcp_rsp)
{
    int rv, len = 0;
    uint8_t cause_value = 0;
    ogs_pfcp_f_seid_t *up_f_seid = NULL;

    ogs_gtp_f_teid_t sgw_s5c_teid, sgw_s5u_teid;
    ogs_gtp_f_teid_t *pgw_s5c_teid = NULL;

    ogs_gtp_xact_t *s11_xact = NULL, *s5c_xact = NULL;
    ogs_gtp_node_t *pgw = NULL;

    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *dl_tunnel = NULL;

    ogs_gtp_create_session_request_t *gtp_req = NULL;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(pfcp_xact);
    ogs_assert(pfcp_rsp);
    ogs_assert(gtp_message);

    gtp_req = &gtp_message->create_session_request;
    ogs_assert(gtp_req);

    s11_xact = pfcp_xact->assoc_xact;
    ogs_assert(s11_xact);

    ogs_pfcp_xact_commit(pfcp_xact);

    cause_value = OGS_GTP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_warn("No Context");
        cause_value = OGS_GTP_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (pfcp_rsp->up_f_seid.presence == 0) {
        ogs_error("No UP F-SEID");
        cause_value = OGS_GTP_CAUSE_MANDATORY_IE_MISSING;
    }

    if (pfcp_rsp->cause.presence) {
        if (pfcp_rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_warn("PFCP Cause [%d] : Not Accepted", pfcp_rsp->cause.u8);
            cause_value = gtp_cause_from_pfcp(pfcp_rsp->cause.u8);
        }
    } else {
        ogs_error("No Cause");
        cause_value = OGS_GTP_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value != OGS_GTP_CAUSE_REQUEST_ACCEPTED) {
        ogs_gtp_send_error_message(s11_xact, sess ? sess->sgw_s5c_teid : 0,
                OGS_GTP_CREATE_SESSION_RESPONSE_TYPE, cause_value);
        return;
    }

    ogs_assert(sess);

    bearer = sgwc_default_bearer_in_sess(sess);
    ogs_assert(bearer);
    dl_tunnel = sgwc_dl_tunnel_in_bearer(bearer);
    ogs_assert(dl_tunnel);

    /* UP F-SEID */
    up_f_seid = pfcp_rsp->up_f_seid.data;
    ogs_assert(up_f_seid);
    sess->sgwu_sxa_seid = be64toh(up_f_seid->seid);

    /* Send Control Plane(DL) : SGW-S5C */
    memset(&sgw_s5c_teid, 0, sizeof(ogs_gtp_f_teid_t));
    sgw_s5c_teid.interface_type = OGS_GTP_F_TEID_S5_S8_SGW_GTP_C;
    sgw_s5c_teid.teid = htobe32(sess->sgw_s5c_teid);
    rv = ogs_gtp_sockaddr_to_f_teid(
        sgwc_self()->gtpc_addr, sgwc_self()->gtpc_addr6, &sgw_s5c_teid, &len);
    ogs_assert(rv == OGS_OK);
    gtp_req->sender_f_teid_for_control_plane.presence = 1;
    gtp_req->sender_f_teid_for_control_plane.data = &sgw_s5c_teid;
    gtp_req->sender_f_teid_for_control_plane.len = len;

    ogs_debug("    SGW_S5C_TEID[0x%x] PGW_S5C_TEID[0x%x]",
        sess->sgw_s5c_teid, sess->pgw_s5c_teid);
    ogs_debug("    SGW_S5U_TEID[%d] PGW_S5U_TEID[%d]",
        dl_tunnel->local_teid, dl_tunnel->remote_teid);

    pgw_s5c_teid = gtp_req->pgw_s5_s8_address_for_control_plane_or_pmip.data;
    ogs_assert(pgw_s5c_teid);

    pgw = ogs_gtp_node_find_by_f_teid(&sgwc_self()->pgw_s5c_list, pgw_s5c_teid);
    if (!pgw) {
        pgw = ogs_gtp_node_add_by_f_teid(
            &sgwc_self()->pgw_s5c_list, pgw_s5c_teid, sgwc_self()->gtpc_port,
            ogs_config()->parameter.no_ipv4,
            ogs_config()->parameter.no_ipv6,
            ogs_config()->parameter.prefer_ipv4);
        ogs_assert(pgw);

        rv = ogs_gtp_connect(
                sgwc_self()->gtpc_sock, sgwc_self()->gtpc_sock6, pgw);
        ogs_assert(rv == OGS_OK);
    }
    /* Setup GTP Node */
    OGS_SETUP_GTP_NODE(sess, pgw);

    /* Remove PGW-S5C */
    gtp_req->pgw_s5_s8_address_for_control_plane_or_pmip.presence = 0;

    /* Data Plane(DL) : SGW-S5U */
    memset(&sgw_s5u_teid, 0, sizeof(ogs_gtp_f_teid_t));
    sgw_s5u_teid.teid = htobe32(dl_tunnel->local_teid);
    sgw_s5u_teid.interface_type = dl_tunnel->interface_type;
    rv = ogs_gtp_sockaddr_to_f_teid(
        dl_tunnel->local_addr, dl_tunnel->local_addr6, &sgw_s5u_teid, &len);
    ogs_assert(rv == OGS_OK);
    gtp_req->bearer_contexts_to_be_created.s5_s8_u_sgw_f_teid.presence = 1;
    gtp_req->bearer_contexts_to_be_created.s5_s8_u_sgw_f_teid.data =
        &sgw_s5u_teid;
    gtp_req->bearer_contexts_to_be_created.s5_s8_u_sgw_f_teid.len = len;

    gtp_message->h.type = OGS_GTP_CREATE_SESSION_REQUEST_TYPE;
    gtp_message->h.teid = sess->pgw_s5c_teid;

    pkbuf = ogs_gtp_build_msg(gtp_message);
    ogs_expect_or_return(pkbuf);

    s5c_xact = ogs_gtp_xact_local_create(
            sess->gnode, &gtp_message->h, pkbuf, timeout, sess);
    ogs_expect_or_return(s5c_xact);

    ogs_gtp_xact_associate(s11_xact, s5c_xact);

    rv = ogs_gtp_xact_commit(s5c_xact);
    ogs_expect(rv == OGS_OK);
}

void sgwc_sxa_handle_session_modification_response(
        sgwc_sess_t *sess, ogs_pfcp_xact_t *pfcp_xact,
        ogs_gtp_message_t *recv_message,
        ogs_pfcp_session_modification_response_t *pfcp_rsp)
{
    int rv, len = 0;
    uint64_t flags;
    uint16_t decoded;

    ogs_gtp_xact_t *s11_xact = NULL;

    sgwc_bearer_t *bearer = NULL;
    sgwc_tunnel_t *tunnel = NULL;
    sgwc_ue_t *sgwc_ue = NULL;

    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(pfcp_xact);
    ogs_assert(pfcp_rsp);
    ogs_assert(recv_message);

    flags = pfcp_xact->modify_flags;
    ogs_assert(flags);

    s11_xact = pfcp_xact->assoc_xact;
    ogs_assert(s11_xact);

    bearer = pfcp_xact->data;
    ogs_assert(bearer);
    sgwc_ue = bearer->sgwc_ue;
    ogs_assert(sgwc_ue);

    ogs_pfcp_xact_commit(pfcp_xact);

    if (flags & OGS_PFCP_MODIFY_ACTIVATE) {
        if (flags & OGS_PFCP_MODIFY_UL_ONLY) {
            ogs_gtp_create_session_response_t *gtp_rsp = NULL;
            ogs_gtp_f_teid_t sgw_s11_teid;
            ogs_gtp_f_teid_t sgw_s1u_teid;

            gtp_rsp = &recv_message->create_session_response;
            ogs_assert(gtp_rsp);

            tunnel = sgwc_ul_tunnel_in_bearer(bearer);
            ogs_assert(tunnel);

            ogs_debug("    ENB_S1U_TEID[%d] SGW_S1U_TEID[%d]",
                tunnel->remote_teid, tunnel->local_teid);

            /* Send Control Plane(UL) : SGW-S11 */
            memset(&sgw_s11_teid, 0, sizeof(ogs_gtp_f_teid_t));
            sgw_s11_teid.interface_type = OGS_GTP_F_TEID_S11_S4_SGW_GTP_C;
            sgw_s11_teid.teid = htobe32(sgwc_ue->sgw_s11_teid);
            rv = ogs_gtp_sockaddr_to_f_teid(
                    sgwc_self()->gtpc_addr, sgwc_self()->gtpc_addr6,
                    &sgw_s11_teid, &len);
            ogs_assert(rv == OGS_OK);
            gtp_rsp->sender_f_teid_for_control_plane.presence = 1;
            gtp_rsp->sender_f_teid_for_control_plane.data = &sgw_s11_teid;
            gtp_rsp->sender_f_teid_for_control_plane.len = len;

            /* Send Data Plane(UL) : SGW-S1U */
            memset(&sgw_s1u_teid, 0, sizeof(ogs_gtp_f_teid_t));
            sgw_s1u_teid.interface_type = tunnel->interface_type;
            sgw_s1u_teid.teid = htobe32(tunnel->local_teid);
            rv = ogs_gtp_sockaddr_to_f_teid(
                tunnel->local_addr, tunnel->local_addr6, &sgw_s1u_teid, &len);
            ogs_assert(rv == OGS_OK);
#if 0
            if (sgwc_self()->gtpu_addr) {
                addr = ogs_hash_get(sgwc_self()->adv_gtpu_hash,
                                &sgwc_self()->gtpu_addr->sin.sin_addr,
                                sizeof(sgwc_self()->gtpu_addr->sin.sin_addr));
            }
            if (sgwc_self()->gtpu_addr6) {
                addr6 = ogs_hash_get(sgwc_self()->adv_gtpu_hash6,
                                &sgwc_self()->gtpu_addr6->sin6.sin6_addr,
                                sizeof(sgwc_self()->gtpu_addr6->sin6.sin6_addr));
            }
            // Swap the SGW-S1U IP to IP to be advertised to UE
            if (addr || addr6) {
                rv = ogs_gtp_sockaddr_to_f_teid(addr, addr6, &sgw_s1u_teid, &len);
                ogs_assert(rv == OGS_OK);
            } else {
                rv = ogs_gtp_sockaddr_to_f_teid(
                        sgwc_self()->gtpu_addr, sgwc_self()->gtpu_addr6,
                        &sgw_s1u_teid, &len);
                ogs_assert(rv == OGS_OK);
            }
#endif
            gtp_rsp->bearer_contexts_created.s1_u_enodeb_f_teid.presence = 1;
            gtp_rsp->bearer_contexts_created.s1_u_enodeb_f_teid.data =
                &sgw_s1u_teid;
            gtp_rsp->bearer_contexts_created.s1_u_enodeb_f_teid.len = len;

            recv_message->h.type = OGS_GTP_CREATE_SESSION_RESPONSE_TYPE;
            recv_message->h.teid = sgwc_ue->mme_s11_teid;

            pkbuf = ogs_gtp_build_msg(recv_message);
            ogs_expect_or_return(pkbuf);

            rv = ogs_gtp_xact_update_tx(s11_xact, &recv_message->h, pkbuf);
            ogs_expect_or_return(rv == OGS_OK);

            rv = ogs_gtp_xact_commit(s11_xact);
            ogs_expect(rv == OGS_OK);

        } else if (flags & OGS_PFCP_MODIFY_DL_ONLY) {
            ogs_gtp_message_t send_message;
            ogs_gtp_modify_bearer_request_t *gtp_req = NULL;
            ogs_gtp_modify_bearer_response_t *gtp_rsp = NULL;

            ogs_gtp_cause_t cause;
            ogs_gtp_uli_t uli;

            gtp_req = &recv_message->modify_bearer_request;
            ogs_assert(gtp_req);

            gtp_rsp = &send_message.modify_bearer_response;
            ogs_assert(gtp_rsp);

            memset(&send_message, 0, sizeof(ogs_gtp_message_t));

            tunnel = sgwc_ul_tunnel_in_bearer(bearer);
            ogs_assert(tunnel);

            memset(&cause, 0, sizeof(cause));
            cause.value = OGS_GTP_CAUSE_REQUEST_ACCEPTED;

            gtp_rsp->cause.presence = 1;
            gtp_rsp->cause.data = &cause;
            gtp_rsp->cause.len = sizeof(cause);

        /* Copy Bearer-Contexts-Modified from Modify-Bearer-Request
         *
         * TS 29.274 Table 7.2.7-2
         * NOTE 1: The SGW shall not change its F-TEID for a given interface
         * during the Handover, Service Request, E-UTRAN Initial Attach,
         * UE Requested PDN connectivity and PDP Context Activation procedures.
         * The SGW F-TEID shall be same for S1-U, S4-U and S12. During Handover
         * and Service Request the target eNodeB/RNC/SGSN may use a different
         * IP type than the one used by the source eNodeB/RNC/SGSN.
         * In order to support such a scenario, the SGW F-TEID should contain
         * both an IPv4 address and an IPv6 address
         * (see also subclause 8.22 "F-TEID").
         */
            gtp_rsp->bearer_contexts_modified.presence = 1;
            gtp_rsp->bearer_contexts_modified.eps_bearer_id.presence = 1;
            gtp_rsp->bearer_contexts_modified.eps_bearer_id.u8 =
                gtp_req->bearer_contexts_to_be_modified.eps_bearer_id.u8;
            gtp_rsp->bearer_contexts_modified.s1_u_enodeb_f_teid.presence = 1;
            gtp_rsp->bearer_contexts_modified.s1_u_enodeb_f_teid.data =
                gtp_req->bearer_contexts_to_be_modified.s1_u_enodeb_f_teid.data;
            gtp_rsp->bearer_contexts_modified.s1_u_enodeb_f_teid.len =
                gtp_req->bearer_contexts_to_be_modified.s1_u_enodeb_f_teid.len;

            gtp_rsp->bearer_contexts_modified.cause.presence = 1;
            gtp_rsp->bearer_contexts_modified.cause.len = sizeof(cause);
            gtp_rsp->bearer_contexts_modified.cause.data = &cause;

            /* if GTP Node changes, End Marker is sent out or not */
            if (gtp_req->user_location_information.presence == 1) {
                /* Set User Location Information */
                decoded = ogs_gtp_parse_uli(
                        &uli, &gtp_req->user_location_information);
                ogs_assert(gtp_req->user_location_information.len == decoded);
                memcpy(&sgwc_ue->e_tai.plmn_id, &uli.tai.plmn_id,
                        sizeof(uli.tai.plmn_id));
                sgwc_ue->e_tai.tac = uli.tai.tac;
                memcpy(&sgwc_ue->e_cgi.plmn_id, &uli.e_cgi.plmn_id,
                        sizeof(uli.e_cgi.plmn_id));
                sgwc_ue->e_cgi.cell_id = uli.e_cgi.cell_id;
                ogs_debug("    TAI[PLMN_ID:%06x,TAC:%d]",
                        ogs_plmn_id_hexdump(&sgwc_ue->e_tai.plmn_id),
                        sgwc_ue->e_tai.tac);
                ogs_debug("    E_CGI[PLMN_ID:%06x,CELL_ID:%d]",
                        ogs_plmn_id_hexdump(&sgwc_ue->e_cgi.plmn_id),
                        sgwc_ue->e_cgi.cell_id);
            }

#if 0
            if (dl_tunnel->gnode && dl_tunnel->gnode != enb) {
                ogs_assert(dl_tunnel->gnode->sock);

                ogs_debug("[SGW] SEND End Marker to ENB[%s]: TEID[0x%x]",
                    OGS_ADDR(&dl_tunnel->gnode->addr, buf),
                    dl_tunnel->remote_teid);
                sgwc_gtp_send_end_marker(dl_tunnel);
            }

            /* Setup GTP Node */
            OGS_SETUP_GTP_NODE(dl_tunnel, enb);

            /* Reset UE state */
            SGW_RESET_UE_STATE(sgwc_ue, SGW_S1U_INACTIVE);
#endif
            send_message.h.type = OGS_GTP_MODIFY_BEARER_RESPONSE_TYPE;
            send_message.h.teid = sgwc_ue->mme_s11_teid;

            pkbuf = ogs_gtp_build_msg(&send_message);
            ogs_expect_or_return(pkbuf);

            rv = ogs_gtp_xact_update_tx(s11_xact, &send_message.h, pkbuf);
            ogs_expect_or_return(rv == OGS_OK);

            rv = ogs_gtp_xact_commit(s11_xact);
            ogs_expect(rv == OGS_OK);

        } else {
            ogs_fatal("Invalid modify_flags[0x%llx]", (long long)flags);
        }

    } else if (flags & OGS_PFCP_MODIFY_REMOVE) {
        sgwc_bearer_remove(bearer);
    }
}

void sgwc_sxa_handle_session_deletion_response(
        sgwc_sess_t *sess, ogs_pfcp_xact_t *pfcp_xact,
        ogs_gtp_message_t *gtp_message,
        ogs_pfcp_session_deletion_response_t *pfcp_rsp)
{
    int rv;
    uint8_t cause_value = 0;
    sgwc_ue_t *sgwc_ue = NULL;
    ogs_gtp_xact_t *s11_xact = NULL;
    ogs_pkbuf_t *pkbuf = NULL;

    ogs_assert(pfcp_xact);
    ogs_assert(pfcp_rsp);

    s11_xact = pfcp_xact->assoc_xact;
    ogs_assert(s11_xact);

    ogs_pfcp_xact_commit(pfcp_xact);

    cause_value = OGS_GTP_CAUSE_REQUEST_ACCEPTED;

    if (!sess) {
        ogs_warn("No Context");
        cause_value = OGS_GTP_CAUSE_CONTEXT_NOT_FOUND;
    }

    if (pfcp_rsp->cause.presence) {
        if (pfcp_rsp->cause.u8 != OGS_PFCP_CAUSE_REQUEST_ACCEPTED) {
            ogs_warn("PFCP Cause[%d] : Not Accepted", pfcp_rsp->cause.u8);
            cause_value = gtp_cause_from_pfcp(pfcp_rsp->cause.u8);
        }
    } else {
        ogs_error("No Cause");
        cause_value = OGS_GTP_CAUSE_MANDATORY_IE_MISSING;
    }

    if (cause_value != OGS_GTP_CAUSE_REQUEST_ACCEPTED) {
        ogs_gtp_send_error_message(s11_xact, sess ? sess->sgw_s5c_teid : 0,
                OGS_GTP_DELETE_SESSION_RESPONSE_TYPE, cause_value);
        return;
    }

    ogs_assert(sess);
    sgwc_ue = sess->sgwc_ue;
    ogs_assert(sgwc_ue);

    gtp_message->h.type = OGS_GTP_DELETE_SESSION_RESPONSE_TYPE;
    gtp_message->h.teid = sgwc_ue->mme_s11_teid;

    pkbuf = ogs_gtp_build_msg(gtp_message);
    ogs_expect_or_return(pkbuf);

    rv = ogs_gtp_xact_update_tx(s11_xact, &gtp_message->h, pkbuf);
    ogs_expect_or_return(rv == OGS_OK);

    rv = ogs_gtp_xact_commit(s11_xact);
    ogs_expect(rv == OGS_OK);

    sgwc_sess_remove(sess);
}
