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
#include "ogs-app.h"

#include "sgwu-sm.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int __sgwu_log_domain;

#undef OGS_LOG_DOMAIN
#define OGS_LOG_DOMAIN __sgwu_log_domain

typedef struct sgwu_tunnel_s sgwu_tunnel_t;

typedef struct sgwu_context_s {
    uint32_t        gtpc_port;      /* Default GTPC port */
    uint32_t        gtpu_port;      /* Default GTPU port */

    ogs_list_t      gtpc_list;      /* SGW GTPC IPv4 Server List */
    ogs_list_t      gtpc_list6;     /* SGW GTPC IPv6 Server List */
    ogs_sock_t      *gtpc_sock;     /* SGW GTPC IPv4 Socket */
    ogs_sock_t      *gtpc_sock6;    /* SGW GTPC IPv6 Socket */
    ogs_sockaddr_t  *gtpc_addr;     /* SGW GTPC IPv4 Address */
    ogs_sockaddr_t  *gtpc_addr6;    /* SGW GTPC IPv6 Address */

    ogs_list_t      gtpu_list;      /* SGW GTPU IPv4 Server List */
    ogs_list_t      gtpu_list6;     /* SGW GTPU IPv6 Server List */
    ogs_list_t      adv_gtpu_list;  /* Advertised SGW GTPU IPv4 Server List */
    ogs_list_t      adv_gtpu_list6; /* Advertised SGW GTPU IPv6 Server List */
    /* Hashtable (SGW GTPU : Advertised SGW GTPU) IPv4 */
    ogs_hash_t      *adv_gtpu_hash;
    /* Hashtable (SGW GTPU : Advertised SGW GTPU) IPv6 */
    ogs_hash_t      *adv_gtpu_hash6;
    ogs_sock_t      *gtpu_sock;     /* SGW GTPU IPv4 Socket */
    ogs_sock_t      *gtpu_sock6;    /* SGW GTPU IPv6 Socket */
    ogs_sockaddr_t  *gtpu_addr;     /* SGW GTPU IPv4 Address */
    ogs_sockaddr_t  *gtpu_addr6;    /* SGW GTPU IPv6 Address */

    ogs_queue_t     *queue;         /* Queue for processing SGW control */
    ogs_timer_mgr_t *timer_mgr;     /* Timer Manager */
    ogs_pollset_t   *pollset;       /* Poll Set for I/O Multiplexing */

    ogs_list_t      mme_s11_list;   /* MME GTPC Node List */
    ogs_list_t      pgw_s5c_list;   /* PGW GTPC Node List */
    ogs_list_t      enb_s1u_list;   /* eNB GTPU Node List */
    ogs_list_t      pgw_s5u_list;   /* PGW GTPU Node List */

    ogs_hash_t      *imsi_ue_hash;  /* hash table (IMSI : SGW_UE) */

    ogs_list_t      sgwu_ue_list;    /* SGW_UE List */
} sgwu_context_t;

typedef struct sgwu_ue_s {
    ogs_lnode_t     lnode;

    uint32_t        sgwu_s11_teid;   /* SGW-S11-TEID is derived from INDEX */
    uint32_t        mme_s11_teid;   /* MME-S11-TEID is received from MME */

    /* UE identity */
    uint8_t         imsi[OGS_MAX_IMSI_LEN];
    int             imsi_len;
    char            imsi_bcd[OGS_MAX_IMSI_BCD_LEN+1];

#define SGW_S1U_INACTIVE  0x0001
#define SGW_DL_NOTI_SENT  0x0002

#define SGW_GET_UE_STATE(__uE)  ((__uE)->state)
#define SGW_SET_UE_STATE(__uE,__sTATE)  ((__uE)->state |= (__sTATE))
#define SGW_RESET_UE_STATE(__uE, __sTATE)  ((__uE)->state &= ~(__sTATE))

    uint32_t        state;

    ogs_list_t      sess_list;

    ogs_gtp_node_t  *gnode;
} sgwu_ue_t;

typedef struct sgwu_sess_s {
    ogs_lnode_t     lnode;      /* A node of list_t */

    /* 
     * SGW-S5C-TEID     = INDEX         | 0x80000000 
     * INDEX            = SGW-S5C-TEID  & ~0x80000000
     */
#define SGW_S5C_TEID_TO_INDEX(__iNDEX) (__iNDEX & ~0x80000000)
#define SGW_S5C_INDEX_TO_TEID(__iNDEX) (__iNDEX | 0x80000000)
    uint32_t        sgwu_s5c_teid;   /* SGW-S5C-TEID is derived from INDEX */    
    uint32_t        pgw_s5c_teid;   /* PGW-S5C-TEID is received from PGW */

    /* APN Configuration */
    ogs_pdn_t       pdn;

    ogs_list_t      bearer_list;

    /* Related Context */
    ogs_gtp_node_t  *gnode;
    sgwu_ue_t        *sgwu_ue;
} sgwu_sess_t;

typedef struct sgwu_bearer_s {
    ogs_lnode_t     lnode;

    uint8_t         ebi;

    /* User-Lication-Info */
    ogs_eps_tai_t   tai;
    ogs_e_cgi_t     e_cgi;

    /* Pkts which will be buffered in case of UE-IDLE */
    uint32_t        num_buffered_pkt;

#define MAX_NUM_OF_PACKET_BUFFER      512 
    ogs_pkbuf_t*    buffered_pkts[MAX_NUM_OF_PACKET_BUFFER];

    ogs_list_t      tunnel_list;
    sgwu_sess_t      *sess;
    sgwu_ue_t        *sgwu_ue;
} sgwu_bearer_t;

typedef struct sgwu_tunnel_s {
    ogs_lnode_t     lnode;

    uint8_t         interface_type;

    uint32_t        local_teid;
    uint32_t        remote_teid;

    /* Related Context */
    sgwu_bearer_t    *bearer;
    ogs_gtp_node_t  *gnode;
} sgwu_tunnel_t;

void sgwu_context_init(void);
void sgwu_context_final(void);
sgwu_context_t *sgwu_self(void);

int sgwu_context_parse_config(void);

sgwu_ue_t *sgwu_ue_add_by_message(ogs_gtp_message_t *message);
sgwu_ue_t *sgwu_ue_find_by_imsi(uint8_t *imsi, int imsi_len);
sgwu_ue_t *sgwu_ue_find_by_imsi_bcd(char *imsi_bcd);
sgwu_ue_t *sgwu_ue_find_by_teid(uint32_t teid);

sgwu_ue_t *sgwu_ue_add(uint8_t *imsi, int imsi_len);
int sgwu_ue_remove(sgwu_ue_t *sgwu_ue);
void sgwu_ue_remove_all(void);

sgwu_sess_t *sgwu_sess_add(sgwu_ue_t *sgwu_ue, char *apn, uint8_t ebi);
int sgwu_sess_remove(sgwu_sess_t *sess);
void sgwu_sess_remove_all(sgwu_ue_t *sgwu_ue);
sgwu_sess_t *sgwu_sess_find_by_apn(sgwu_ue_t *sgwu_ue, char *apn);
sgwu_sess_t *sgwu_sess_find_by_ebi(sgwu_ue_t *sgwu_ue, uint8_t ebi);
sgwu_sess_t *sgwu_sess_find_by_teid(uint32_t teid);
sgwu_sess_t *sgwu_sess_first(sgwu_ue_t *sgwu_ue);
sgwu_sess_t *sgwu_sess_next(sgwu_sess_t *sess);

sgwu_bearer_t *sgwu_bearer_add(sgwu_sess_t *sess);
int sgwu_bearer_remove(sgwu_bearer_t *bearer);
void sgwu_bearer_remove_all(sgwu_sess_t *sess);
sgwu_bearer_t *sgwu_bearer_find_by_sgwu_s5u_teid(
                                uint32_t sgwu_s5u_teid);
sgwu_bearer_t *sgwu_bearer_find_by_sess_ebi(
                                sgwu_sess_t *sess, uint8_t ebi);
sgwu_bearer_t *sgwu_bearer_find_by_ue_ebi(
                                sgwu_ue_t *sgwu_ue, uint8_t ebi);
sgwu_bearer_t *sgwu_default_bearer_in_sess(sgwu_sess_t *sess);
sgwu_bearer_t *sgwu_bearer_first(sgwu_sess_t *sess);
sgwu_bearer_t *sgwu_bearer_next(sgwu_bearer_t *bearer);

sgwu_tunnel_t *sgwu_tunnel_add(
        sgwu_bearer_t *bearer, uint8_t interface_type);
int sgwu_tunnel_remove(sgwu_tunnel_t *tunnel);
void sgwu_tunnel_remove_all(sgwu_bearer_t *bearer);
sgwu_tunnel_t *sgwu_tunnel_find_by_teid(uint32_t teid);
sgwu_tunnel_t *sgwu_tunnel_find_by_interface_type(
        sgwu_bearer_t *bearer, uint8_t interface_type);
sgwu_tunnel_t *sgwu_s1u_tunnel_in_bearer(sgwu_bearer_t *bearer);
sgwu_tunnel_t *sgwu_s5u_tunnel_in_bearer(sgwu_bearer_t *bearer);
sgwu_tunnel_t *sgwu_tunnel_first(sgwu_bearer_t *bearer);
sgwu_tunnel_t *sgwu_tunnel_next(sgwu_tunnel_t *tunnel);

#ifdef __cplusplus
}
#endif

#endif /* SGWU_CONTEXT_H */
