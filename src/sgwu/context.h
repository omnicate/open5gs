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

#ifndef SGWU_CONTEXT_H
#define SGWU_CONTEXT_H

#include "ogs-gtp.h"
#include "ogs-pfcp.h"
#include "ogs-app.h"

#include "timer.h"
#include "sgwu-sm.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __sgwu_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __sgwu_log_domain

typedef struct sgwu_context_s {
    uint32_t        gtpu_port;      /* Default: SGWU GTP-U local port */

    ogs_list_t      gtpu_list;      /* SGWU GTPU Server List */
    ogs_sock_t      *gtpu_sock;     /* SGWU GTPU IPv4 Socket */
    ogs_sock_t      *gtpu_sock6;    /* SGWU GTPU IPv6 Socket */
    ogs_list_t      gtpu_resource_list; /* UP IP Resource List */
    uint16_t        function_features; /* UP Function Features */

    ogs_queue_t     *queue;         /* Queue for processing SGWU control */
    ogs_timer_mgr_t *timer_mgr;     /* Timer Manager */
    ogs_pollset_t   *pollset;       /* Poll Set for I/O Multiplexing */

    ogs_list_t      gnb_n3_list;    /* gNB N3 Node List */
    ogs_list_t      ip_pool_list;

    ogs_hash_t      *sess_hash;     /* hash table (F-SEID) */
    ogs_hash_t      *ipv4_hash;     /* hash table (IPv4 Address) */
    ogs_hash_t      *ipv6_hash;     /* hash table (IPv6 Address) */

    ogs_list_t      sess_list;
} sgwu_context_t;

#define SGWU_SESS(pfcp_sess) ogs_container_of(pfcp_sess, sgwu_sess_t, pfcp)
typedef struct sgwu_sess_s {
    ogs_lnode_t     lnode;
    uint32_t        index;              /**< An index of this node */

    ogs_pfcp_sess_t pfcp;
    ogs_list_t      sdf_filter_list;    /* SDF Filter List */

    uint64_t        sgwu_n4_seid;        /* SGWU SEID is dervied from INDEX */
    uint64_t        smf_n4_seid;        /* SMF SEID is received from Peer */

    /* APN Configuration */
    ogs_pdn_t       pdn;
    ogs_pfcp_ue_ip_t *ipv4;
    ogs_pfcp_ue_ip_t *ipv6;

    char            *gx_sid;            /* Gx Session ID */
    ogs_pfcp_node_t *pfcp_node;
} sgwu_sess_t;

void sgwu_context_init(void);
void sgwu_context_final(void);
sgwu_context_t *sgwu_self(void);

int sgwu_context_parse_config(void);

sgwu_sess_t *sgwu_sess_add_by_message(ogs_pfcp_message_t *message);

sgwu_sess_t *sgwu_sess_add(ogs_pfcp_f_seid_t *f_seid,
        const char *apn, uint8_t pdn_type, ogs_pfcp_ue_ip_addr_t *ue_ip,
        ogs_pfcp_pdr_id_t default_pdr_id);
int sgwu_sess_remove(sgwu_sess_t *sess);
void sgwu_sess_remove_all(void);
sgwu_sess_t *sgwu_sess_find(uint32_t index);
sgwu_sess_t *sgwu_sess_find_by_cp_seid(uint64_t seid);
sgwu_sess_t *sgwu_sess_find_by_up_seid(uint64_t seid);
sgwu_sess_t *sgwu_sess_find_by_ipv4(uint32_t addr);
sgwu_sess_t *sgwu_sess_find_by_ipv6(uint32_t *addr6);

#ifdef __cplusplus
}
#endif

#endif /* SGWU_CONTEXT_H */
