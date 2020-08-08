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

#ifndef OGS_PFCP_HANDLER_H
#define OGS_PFCP_HANDLER_H

#ifdef __cplusplus
extern "C" {
#endif

void ogs_pfcp_handle_heartbeat_request(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_heartbeat_request_t *req);
void ogs_pfcp_handle_heartbeat_response(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_heartbeat_response_t *req);

void ogs_pfcp_cp_handle_association_setup_request(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_association_setup_request_t *req);
void ogs_pfcp_cp_handle_association_setup_response(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_association_setup_response_t *req);

void ogs_pfcp_up_handle_association_setup_request(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_association_setup_request_t *req);
void ogs_pfcp_up_handle_association_setup_response(
        ogs_pfcp_node_t *node, ogs_pfcp_xact_t *xact,
        ogs_pfcp_association_setup_response_t *req);

#define OGS_PFCP_UP_HANDLED     1
int ogs_pfcp_up_handle_pdr(ogs_pfcp_pdr_t *pdr, ogs_pkbuf_t *recvbuf);

#ifdef __cplusplus
}
#endif

#endif /* OGS_PFCP_HANDLER_H */
