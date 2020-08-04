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

#ifndef SGWC_PFCP_PATH_H
#define SGWC_PFCP_PATH_H

#include "sxa-build.h"

#ifdef __cplusplus
extern "C" {
#endif

int sgwc_pfcp_open(void);
void sgwc_pfcp_close(void);

void sgwc_pfcp_send_association_setup_request(ogs_pfcp_node_t *node);
void sgwc_pfcp_send_association_setup_response(ogs_pfcp_xact_t *xact,
        uint8_t cause);
void sgwc_pfcp_send_heartbeat_request(ogs_pfcp_node_t *node);

#if 0
void sgwc_5gc_pfcp_send_session_establishment_request(
        sgwc_sess_t *sess, ogs_sbi_session_t *session);
void sgwc_5gc_pfcp_send_session_modification_request(
        sgwc_sess_t *sess, ogs_sbi_session_t *session, uint64_t flags);
void sgwc_5gc_pfcp_send_session_deletion_request(
        sgwc_sess_t *sess, ogs_sbi_session_t *session, int trigger);

void sgwc_epc_pfcp_send_session_establishment_request(
        sgwc_sess_t *sess, void *gtp_xact);
void sgwc_epc_pfcp_send_session_modification_request(sgwc_bearer_t *bearer);
void sgwc_epc_pfcp_send_session_deletion_request(
        sgwc_sess_t *sess, void *gtp_xact);

void sgwc_5gc_pfcp_send_qos_flow_modification_request(sgwc_bearer_t *qos_flow,
        ogs_sbi_session_t *session, uint64_t flags);
#endif

#ifdef __cplusplus
}
#endif

#endif /* SGWC_PFCP_PATH_H */
