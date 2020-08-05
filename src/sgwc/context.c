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

#include <yaml.h>

#include "context.h"

static sgwc_context_t self;

int __sgwc_log_domain;

static OGS_POOL(sgwc_ue_pool, sgwc_ue_t);
static OGS_POOL(sgwc_sess_pool, sgwc_sess_t);
static OGS_POOL(sgwc_bearer_pool, sgwc_bearer_t);
static OGS_POOL(sgwc_tunnel_pool, sgwc_tunnel_t);

static int context_initialized = 0;

void sgwc_context_init(void)
{
    ogs_assert(context_initialized == 0);

    memset(&self, 0, sizeof(sgwc_context_t));

    ogs_log_install_domain(&__ogs_gtp_domain, "gtp", ogs_core()->log.level);
    ogs_log_install_domain(&__sgwc_log_domain, "sgwc", ogs_core()->log.level);

    ogs_list_init(&self.gtpc_list);
    ogs_list_init(&self.gtpc_list6);
    ogs_list_init(&self.gtpu_list);
    ogs_list_init(&self.gtpu_list6);
    ogs_list_init(&self.adv_gtpu_list);
    ogs_list_init(&self.adv_gtpu_list6);

    self.adv_gtpu_hash = ogs_hash_make();
    self.adv_gtpu_hash6 = ogs_hash_make();

    ogs_gtp_node_init(512);
    ogs_list_init(&self.mme_s11_list);
    ogs_list_init(&self.pgw_s5c_list);
    ogs_list_init(&self.enb_s1u_list);
    ogs_list_init(&self.pgw_s5u_list);

    ogs_pool_init(&sgwc_ue_pool, ogs_config()->pool.ue);
    ogs_pool_init(&sgwc_sess_pool, ogs_config()->pool.sess);
    ogs_pool_init(&sgwc_bearer_pool, ogs_config()->pool.bearer);
    ogs_pool_init(&sgwc_tunnel_pool, ogs_config()->pool.tunnel);

    self.imsi_ue_hash = ogs_hash_make();

    ogs_list_init(&self.sgw_ue_list);

    context_initialized = 1;
}

void sgwc_context_final(void)
{
    ogs_assert(context_initialized == 1);

    sgwc_ue_remove_all();

    ogs_assert(self.imsi_ue_hash);
    ogs_hash_destroy(self.imsi_ue_hash);

    ogs_assert(self.adv_gtpu_hash);
    ogs_hash_destroy(self.adv_gtpu_hash);
    ogs_assert(self.adv_gtpu_hash6);
    ogs_hash_destroy(self.adv_gtpu_hash6);

    ogs_pool_final(&sgwc_tunnel_pool);
    ogs_pool_final(&sgwc_bearer_pool);
    ogs_pool_final(&sgwc_sess_pool);
    ogs_pool_final(&sgwc_ue_pool);

    ogs_gtp_node_remove_all(&self.mme_s11_list);
    ogs_gtp_node_remove_all(&self.pgw_s5c_list);
    ogs_gtp_node_remove_all(&self.enb_s1u_list);
    ogs_gtp_node_remove_all(&self.pgw_s5u_list);
    ogs_gtp_node_final();

    context_initialized = 0;
}

sgwc_context_t *sgwc_self(void)
{
    return &self;
}

static int sgwc_context_prepare(void)
{
    self.gtpc_port = OGS_GTPV2_C_UDP_PORT;
    self.gtpu_port = OGS_GTPV1_U_UDP_PORT;

    return OGS_OK;
}

static int sgwc_context_validation(void)
{
    if (ogs_list_empty(&self.gtpc_list) &&
        ogs_list_empty(&self.gtpc_list6)) {
        ogs_error("No sgwc.gtpc in '%s'", ogs_config()->file);
        return OGS_ERROR;
    }
    return OGS_OK;
}

int sgwc_context_parse_config(void)
{
    int rv;
    yaml_document_t *document = NULL;
    ogs_yaml_iter_t root_iter;

    document = ogs_config()->document;
    ogs_assert(document);

    rv = sgwc_context_prepare();
    if (rv != OGS_OK) return rv;

    ogs_yaml_iter_init(&root_iter, document);
    while (ogs_yaml_iter_next(&root_iter)) {
        const char *root_key = ogs_yaml_iter_key(&root_iter);
        ogs_assert(root_key);
        if (!strcmp(root_key, "sgwc")) {
            ogs_yaml_iter_t sgwc_iter;
            ogs_yaml_iter_recurse(&root_iter, &sgwc_iter);
            while (ogs_yaml_iter_next(&sgwc_iter)) {
                const char *sgwc_key = ogs_yaml_iter_key(&sgwc_iter);
                ogs_assert(sgwc_key);
                if (!strcmp(sgwc_key, "gtpc")) {
                    ogs_yaml_iter_t gtpc_array, gtpc_iter;
                    ogs_yaml_iter_recurse(&sgwc_iter, &gtpc_array);
                    do {
                        int family = AF_UNSPEC;
                        int i, num = 0;
                        const char *hostname[OGS_MAX_NUM_OF_HOSTNAME];
                        uint16_t port = self.gtpc_port;
                        const char *dev = NULL;
                        ogs_sockaddr_t *addr = NULL;

                        if (ogs_yaml_iter_type(&gtpc_array) ==
                                YAML_MAPPING_NODE) {
                            memcpy(&gtpc_iter, &gtpc_array,
                                    sizeof(ogs_yaml_iter_t));
                        } else if (ogs_yaml_iter_type(&gtpc_array) ==
                            YAML_SEQUENCE_NODE) {
                            if (!ogs_yaml_iter_next(&gtpc_array))
                                break;
                            ogs_yaml_iter_recurse(&gtpc_array, &gtpc_iter);
                        } else if (ogs_yaml_iter_type(&gtpc_array) ==
                            YAML_SCALAR_NODE) {
                            break;
                        } else
                            ogs_assert_if_reached();

                        while (ogs_yaml_iter_next(&gtpc_iter)) {
                            const char *gtpc_key =
                                ogs_yaml_iter_key(&gtpc_iter);
                            ogs_assert(gtpc_key);
                            if (!strcmp(gtpc_key, "family")) {
                                const char *v = ogs_yaml_iter_value(&gtpc_iter);
                                if (v) family = atoi(v);
                                if (family != AF_UNSPEC &&
                                    family != AF_INET && family != AF_INET6) {
                                    ogs_warn("Ignore family(%d) : "
                                        "AF_UNSPEC(%d), "
                                        "AF_INET(%d), AF_INET6(%d) ", 
                                        family, AF_UNSPEC, AF_INET, AF_INET6);
                                    family = AF_UNSPEC;
                                }
                            } else if (!strcmp(gtpc_key, "addr") ||
                                    !strcmp(gtpc_key, "name")) {
                                ogs_yaml_iter_t hostname_iter;
                                ogs_yaml_iter_recurse(&gtpc_iter,
                                        &hostname_iter);
                                ogs_assert(ogs_yaml_iter_type(&hostname_iter) !=
                                    YAML_MAPPING_NODE);

                                do {
                                    if (ogs_yaml_iter_type(&hostname_iter) ==
                                            YAML_SEQUENCE_NODE) {
                                        if (!ogs_yaml_iter_next(&hostname_iter))
                                            break;
                                    }

                                    ogs_assert(num <= OGS_MAX_NUM_OF_HOSTNAME);
                                    hostname[num++] = 
                                        ogs_yaml_iter_value(&hostname_iter);
                                } while (
                                    ogs_yaml_iter_type(&hostname_iter) ==
                                        YAML_SEQUENCE_NODE);
                            } else if (!strcmp(gtpc_key, "port")) {
                                const char *v = ogs_yaml_iter_value(&gtpc_iter);
                                if (v) port = atoi(v);
                            } else if (!strcmp(gtpc_key, "dev")) {
                                dev = ogs_yaml_iter_value(&gtpc_iter);
                            } else
                                ogs_warn("unknown key `%s`", gtpc_key);
                        }

                        addr = NULL;
                        for (i = 0; i < num; i++) {
                            rv = ogs_addaddrinfo(&addr,
                                    family, hostname[i], port, 0);
                            ogs_assert(rv == OGS_OK);
                        }

                        if (addr) {
                            if (ogs_config()->parameter.no_ipv4 == 0)
                                ogs_socknode_add(
                                        &self.gtpc_list, AF_INET, addr);
                            if (ogs_config()->parameter.no_ipv6 == 0)
                                ogs_socknode_add(
                                        &self.gtpc_list6, AF_INET6, addr);
                            ogs_freeaddrinfo(addr);
                        }

                        if (dev) {
                            rv = ogs_socknode_probe(
                                    ogs_config()->parameter.no_ipv4 ?
                                        NULL : &self.gtpc_list,
                                    ogs_config()->parameter.no_ipv6 ?
                                        NULL : &self.gtpc_list6,
                                    dev, port);
                            ogs_assert(rv == OGS_OK);
                        }

                    } while (ogs_yaml_iter_type(&gtpc_array) == 
                            YAML_SEQUENCE_NODE);

                    if (ogs_list_empty(&self.gtpc_list) &&
                        ogs_list_empty(&self.gtpc_list6)) {
                        rv = ogs_socknode_probe(
                                ogs_config()->parameter.no_ipv4 ?
                                    NULL : &self.gtpc_list,
                                ogs_config()->parameter.no_ipv6 ?
                                    NULL : &self.gtpc_list6,
                                NULL, self.gtpc_port);
                        ogs_assert(rv == OGS_OK);
                    }
                } else if (!strcmp(sgwc_key, "pfcp")) {
                    /* handle config in pfcp library */
                } else
                    ogs_warn("unknown key `%s`", sgwc_key);
            }
        }
    }

    rv = sgwc_context_validation();
    if (rv != OGS_OK) return rv;

    return OGS_OK;
}

sgwc_ue_t *sgwc_ue_add_by_message(ogs_gtp_message_t *message)
{
    sgwc_ue_t *sgwc_ue = NULL;
    ogs_gtp_create_session_request_t *req = &message->create_session_request;

    ogs_assert(message);

    req = &message->create_session_request;
    if (req->imsi.presence == 0) {
        ogs_error("No IMSI");
        return NULL;
    }

    ogs_trace("sgwc_ue_add_by_message() - IMSI ");
    ogs_log_hexdump(OGS_LOG_TRACE, req->imsi.data, req->imsi.len);

    /* 
     * 7.2.1 in 3GPP TS 29.274 Release 15
     *
     * If the new Create Session Request received by the SGW collides with
     * an existing active PDN connection context (the existing PDN connection
     * context is identified with the tuple [IMSI, EPS Bearer ID], where IMSI
     * shall be replaced by TAC and SNR part of ME Identity for emergency
     * attached UE without UICC or authenticated IMSI), this Create Session
     * Request shall be treated as a request for a new session. Before creating
     * the new session, the SGW should delete:
     *
     * - the existing PDN connection context locally, if the Create Session
     *   Request is received with the TEID set to zero in the header, or
     *   if it is received with a TEID not set to zero in the header and
     *   it collides with the default bearer of an existing PDN connection
     *   context;
     * - the existing dedicated bearer context locally, if the Create Session
     *   Request collides with an existing dedicated bearer context and
     *   the message is received with a TEID not set to zero in the header.
     */
    sgwc_ue = sgwc_ue_find_by_imsi(req->imsi.data, req->imsi.len);
    if (sgwc_ue)
        sgwc_ue_remove(sgwc_ue);
    sgwc_ue = sgwc_ue_add(req->imsi.data, req->imsi.len);
    ogs_assert(sgwc_ue);

    return sgwc_ue;
}

sgwc_ue_t *sgwc_ue_add(uint8_t *imsi, int imsi_len)
{
    sgwc_ue_t *sgwc_ue = NULL;

    ogs_assert(imsi);
    ogs_assert(imsi_len);

    ogs_pool_alloc(&sgwc_ue_pool, &sgwc_ue);
    ogs_assert(sgwc_ue);
    memset(sgwc_ue, 0, sizeof *sgwc_ue);

    sgwc_ue->sgw_s11_teid = ogs_pool_index(&sgwc_ue_pool, sgwc_ue);
    ogs_assert(sgwc_ue->sgw_s11_teid > 0 &&
                sgwc_ue->sgw_s11_teid <= ogs_config()->pool.ue);

    /* Set IMSI */
    sgwc_ue->imsi_len = imsi_len;
    memcpy(sgwc_ue->imsi, imsi, sgwc_ue->imsi_len);
    ogs_buffer_to_bcd(sgwc_ue->imsi, sgwc_ue->imsi_len, sgwc_ue->imsi_bcd);

    ogs_list_init(&sgwc_ue->sess_list);

    ogs_hash_set(self.imsi_ue_hash, sgwc_ue->imsi, sgwc_ue->imsi_len, sgwc_ue);

    ogs_list_add(&self.sgw_ue_list, sgwc_ue);

    return sgwc_ue;
}

int sgwc_ue_remove(sgwc_ue_t *sgwc_ue)
{
    ogs_assert(sgwc_ue);

    ogs_list_remove(&self.sgw_ue_list, sgwc_ue);

    ogs_hash_set(self.imsi_ue_hash, sgwc_ue->imsi, sgwc_ue->imsi_len, NULL);

    sgwc_sess_remove_all(sgwc_ue);

    ogs_pool_free(&sgwc_ue_pool, sgwc_ue);

    return OGS_OK;
}

void sgwc_ue_remove_all(void)
{
    sgwc_ue_t *sgwc_ue = NULL, *next = NULL;;

    ogs_list_for_each_safe(&self.sgw_ue_list, next, sgwc_ue)
        sgwc_ue_remove(sgwc_ue);
}

sgwc_ue_t *sgwc_ue_find_by_imsi_bcd(char *imsi_bcd)
{
    uint8_t imsi[OGS_MAX_IMSI_LEN];
    int imsi_len = 0;

    ogs_assert(imsi_bcd);

    ogs_bcd_to_buffer(imsi_bcd, imsi, &imsi_len);

    return sgwc_ue_find_by_imsi(imsi, imsi_len);
}

sgwc_ue_t *sgwc_ue_find_by_imsi(uint8_t *imsi, int imsi_len)
{
    ogs_assert(imsi && imsi_len);

    return (sgwc_ue_t *)ogs_hash_get(self.imsi_ue_hash, imsi, imsi_len);
}

sgwc_ue_t *sgwc_ue_find_by_teid(uint32_t teid)
{
    return ogs_pool_find(&sgwc_ue_pool, teid);
}

sgwc_sess_t *sgwc_sess_add(sgwc_ue_t *sgwc_ue, char *apn)
{
    sgwc_sess_t *sess = NULL;

    ogs_assert(sgwc_ue);

    ogs_pool_alloc(&sgwc_sess_pool, &sess);
    if (!sess) {
        ogs_error("Maximum number of session[%d] reached",
                    ogs_config()->pool.sess);
        return NULL;
    }
    memset(sess, 0, sizeof *sess);

    sess->index = ogs_pool_index(&sgwc_sess_pool, sess);
    ogs_assert(sess->index > 0 && sess->index <= ogs_config()->pool.sess);

    /* Set TEID & SEID */
    sess->sgw_s5c_teid = sess->index;
    sess->sgwc_sxa_seid = sess->index;

    /* Set APN */
    ogs_cpystrn(sess->pdn.apn, apn, OGS_MAX_APN_LEN+1);

    sess->sgwc_ue = sgwc_ue;

    ogs_list_add(&sgwc_ue->sess_list, sess);

    return sess;
}

static bool compare_ue_info(ogs_pfcp_node_t *node, sgwc_sess_t *sess)
{
    sgwc_ue_t *sgwc_ue = NULL;
    int i;

    ogs_assert(node);
    ogs_assert(sess);
    sgwc_ue = sess->sgwc_ue;
    ogs_assert(sgwc_ue);

    for (i = 0; i < node->num_of_tac; i++)
        if (node->tac[i] == sgwc_ue->e_tai.tac) return true;

    for (i = 0; i < node->num_of_e_cell_id; i++)
        if (node->e_cell_id[i] == sgwc_ue->e_cgi.cell_id) return true;

    for (i = 0; i < node->num_of_apn; i++)
        if (strcmp(node->apn[i], sess->pdn.apn) == 0) return true;

    return false;
}

static ogs_pfcp_node_t *selected_sgwu_node(
        ogs_pfcp_node_t *current, sgwc_sess_t *sess)
{
    ogs_pfcp_node_t *next, *node;

    ogs_assert(current);
    ogs_assert(sess);

    next = ogs_list_next(current);
    for (node = next; node; node = ogs_list_next(node)) {
        if (OGS_FSM_CHECK(&node->sm, sgwc_pfcp_state_associated) &&
            compare_ue_info(node, sess) == true) return node;
    }

    for (node = ogs_list_first(&ogs_pfcp_self()->peer_list);
            node != next; node = ogs_list_next(node)) {
        if (OGS_FSM_CHECK(&node->sm, sgwc_pfcp_state_associated) &&
            compare_ue_info(node, sess) == true) return node;
    }

    return next ? next : ogs_list_first(&ogs_pfcp_self()->peer_list);
}

void sgwc_sess_select_sgwu(sgwc_sess_t *sess)
{
    char buf[OGS_ADDRSTRLEN];

    ogs_assert(sess);

    /*
     * When used for the first time, if last node is set,
     * the search is performed from the first SGW-U in a round-robin manner.
     */
    if (ogs_pfcp_self()->node == NULL)
        ogs_pfcp_self()->node = ogs_list_last(&ogs_pfcp_self()->peer_list);

    /* setup GTP session with selected SGW-U */
    ogs_pfcp_self()->node = selected_sgwu_node(ogs_pfcp_self()->node, sess);
    ogs_assert(ogs_pfcp_self()->node);
    OGS_SETUP_PFCP_NODE(sess, ogs_pfcp_self()->node);
    ogs_debug("UE using SGW-U on IP[%s]",
            OGS_ADDR(&ogs_pfcp_self()->node->addr, buf));

    /* iterate to next SGW-U in list for next UE attach */
    ogs_pfcp_self()->node = ogs_list_next(ogs_pfcp_self()->node);
}

int sgwc_sess_remove(sgwc_sess_t *sess)
{
    sgwc_ue_t *sgwc_ue = NULL;

    ogs_assert(sess);
    sgwc_ue = sess->sgwc_ue;
    ogs_assert(sgwc_ue);

    ogs_list_remove(&sgwc_ue->sess_list, sess);

    sgwc_bearer_remove_all(sess);

    ogs_pool_free(&sgwc_sess_pool, sess);

    return OGS_OK;
}

void sgwc_sess_remove_all(sgwc_ue_t *sgwc_ue)
{
    sgwc_sess_t *sess = NULL, *next_sess = NULL;
    
    ogs_assert(sgwc_ue);
    ogs_list_for_each_safe(&sgwc_ue->sess_list, next_sess, sess)
        sgwc_sess_remove(sess);
}

sgwc_sess_t *sgwc_sess_find(uint32_t index)
{
    ogs_assert(index);
    return ogs_pool_find(&sgwc_sess_pool, index);
}

sgwc_sess_t* sgwc_sess_find_by_teid(uint32_t teid)
{
    return ogs_pool_find(&sgwc_sess_pool, teid);
}

sgwc_sess_t *sgwc_sess_find_by_seid(uint64_t seid)
{
    return sgwc_sess_find(seid);
}

sgwc_sess_t* sgwc_sess_find_by_apn(sgwc_ue_t *sgwc_ue, char *apn)
{
    sgwc_sess_t *sess = NULL;

    ogs_assert(sgwc_ue);
    ogs_assert(apn);

    ogs_list_for_each(&sgwc_ue->sess_list, sess) {
        if (!strcmp(sess->pdn.apn, apn))
            return sess;
    }

    return NULL;
}

sgwc_sess_t *sgwc_sess_find_by_ebi(sgwc_ue_t *sgwc_ue, uint8_t ebi)
{
    sgwc_bearer_t *bearer = NULL;
    ogs_assert(sgwc_ue);

    bearer = sgwc_bearer_find_by_ue_ebi(sgwc_ue, ebi);
    if (bearer)
        return bearer->sess;

    return NULL;
}

sgwc_sess_t* sgwc_sess_first(sgwc_ue_t *sgwc_ue)
{
    ogs_assert(sgwc_ue);
    return ogs_list_first(&sgwc_ue->sess_list);
}

sgwc_sess_t* sgwc_sess_next(sgwc_sess_t *sess)
{
    ogs_assert(sess);
    return ogs_list_next(sess);
}

sgwc_bearer_t* sgwc_bearer_add(sgwc_sess_t *sess)
{
    sgwc_bearer_t *bearer = NULL;
    ogs_pfcp_gtpu_resource_t *resource = NULL;

    ogs_pfcp_pdr_t *dl_pdr = NULL;
    ogs_pfcp_pdr_t *ul_pdr = NULL;
    ogs_pfcp_far_t *dl_far = NULL;
    ogs_pfcp_far_t *ul_far = NULL;

    sgwc_tunnel_t *tunnel = NULL;
    sgwc_ue_t *sgwc_ue = NULL;

    ogs_assert(sess);
    sgwc_ue = sess->sgwc_ue;
    ogs_assert(sgwc_ue);

    ogs_pool_alloc(&sgwc_bearer_pool, &bearer);
    ogs_assert(bearer);
    memset(bearer, 0, sizeof *bearer);

    bearer->sgwc_ue = sgwc_ue;
    bearer->sess = sess;

    ogs_list_init(&bearer->tunnel_list);

    tunnel = sgwc_tunnel_add(bearer, OGS_GTP_F_TEID_S1_U_SGW_GTP_U);
    ogs_assert(tunnel);

    tunnel = sgwc_tunnel_add(bearer, OGS_GTP_F_TEID_S5_S8_SGW_GTP_U);
    ogs_assert(tunnel);

    bearer->index = ogs_pool_index(&sgwc_bearer_pool, bearer);
    ogs_assert(bearer->index > 0 && bearer->index <= ogs_config()->pool.bearer);

    dl_pdr = ogs_pfcp_pdr_add(&bearer->pfcp);
    ogs_assert(dl_pdr);
    dl_pdr->id = OGS_NEXT_ID(sess->pdr_id, 1, OGS_MAX_NUM_OF_PDR+1);
    dl_pdr->src_if = OGS_PFCP_INTERFACE_CORE;

    ul_pdr = ogs_pfcp_pdr_add(&bearer->pfcp);
    ogs_assert(ul_pdr);
    ul_pdr->id = OGS_NEXT_ID(sess->pdr_id, 1, OGS_MAX_NUM_OF_PDR+1);
    ul_pdr->src_if = OGS_PFCP_INTERFACE_ACCESS;

    dl_far = ogs_pfcp_far_add(&bearer->pfcp);
    ogs_assert(dl_far);
    dl_far->id = OGS_NEXT_ID(sess->far_id, 1, OGS_MAX_NUM_OF_FAR+1);
    dl_far->dst_if = OGS_PFCP_INTERFACE_ACCESS;
    ogs_pfcp_pdr_associate_far(dl_pdr, dl_far);

    ul_far = ogs_pfcp_far_add(&bearer->pfcp);
    ogs_assert(ul_far);
    ul_far->id = OGS_NEXT_ID(sess->far_id, 1, OGS_MAX_NUM_OF_FAR+1);
    ul_far->dst_if = OGS_PFCP_INTERFACE_CORE;
    ogs_pfcp_pdr_associate_far(ul_pdr, ul_far);

    ogs_assert(sess->pfcp_node);
    resource = ogs_pfcp_gtpu_resource_find(
            &sess->pfcp_node->gtpu_resource_list,
            sess->pdn.apn, OGS_PFCP_INTERFACE_ACCESS);
    if (resource) {
        ogs_pfcp_user_plane_ip_resource_info_to_sockaddr(&resource->info,
            &bearer->sgw_s5u_addr, &bearer->sgw_s5u_addr6);
        ogs_assert(bearer->sgw_s5u_addr || bearer->sgw_s5u_addr6);
        if (resource->info.teidri)
            bearer->sgw_s5u_teid = OGS_PFCP_GTPU_INDEX_TO_TEID(
                    bearer->index, resource->info.teidri,
                    resource->info.teid_range);
        else
            bearer->sgw_s5u_teid = bearer->index;
    } else {
        if (sess->pfcp_node->addr.ogs_sa_family == AF_INET)
            ogs_copyaddrinfo(&bearer->sgw_s5u_addr, &sess->pfcp_node->addr);
        else if (sess->pfcp_node->addr.ogs_sa_family == AF_INET6)
            ogs_copyaddrinfo(&bearer->sgw_s5u_addr6, &sess->pfcp_node->addr);
        else
            ogs_assert_if_reached();
        ogs_assert(bearer->sgw_s5u_addr || bearer->sgw_s5u_addr6);

        bearer->sgw_s5u_teid = bearer->index;
    }

    ogs_pfcp_sockaddr_to_f_teid(bearer->sgw_s5u_addr, bearer->sgw_s5u_addr6,
            &ul_pdr->f_teid, &ul_pdr->f_teid_len);
    ul_pdr->f_teid.teid = bearer->sgw_s5u_teid;

    ogs_list_add(&sess->bearer_list, bearer);
    
    return bearer;
}

int sgwc_bearer_remove(sgwc_bearer_t *bearer)
{
    int i;

    ogs_assert(bearer);
    ogs_assert(bearer->sess);

    ogs_list_remove(&bearer->sess->bearer_list, bearer);
    ogs_pfcp_sess_clear(&bearer->pfcp);

    if (bearer->sgw_s5u_addr)
        ogs_freeaddrinfo(bearer->sgw_s5u_addr);
    if (bearer->sgw_s5u_addr6)
        ogs_freeaddrinfo(bearer->sgw_s5u_addr6);

    sgwc_tunnel_remove_all(bearer);

    /* Free the buffered packets */
    for (i = 0; i < bearer->num_buffered_pkt; i++)
        ogs_pkbuf_free(bearer->buffered_pkts[i]);

    ogs_pool_free(&sgwc_bearer_pool, bearer);

    return OGS_OK;
}

void sgwc_bearer_remove_all(sgwc_sess_t *sess)
{
    sgwc_bearer_t *bearer = NULL, *next_bearer = NULL;

    ogs_assert(sess);
    ogs_list_for_each_safe(&sess->bearer_list, next_bearer, bearer)
        sgwc_bearer_remove(bearer);
}

sgwc_bearer_t *sgwc_bearer_find_by_sgwc_s5u_teid(uint32_t sgwc_s5u_teid)
{
    return ogs_pool_find(&sgwc_bearer_pool, sgwc_s5u_teid);
}

sgwc_bearer_t *sgwc_bearer_find_by_sess_ebi(sgwc_sess_t *sess, uint8_t ebi)
{
    sgwc_bearer_t *bearer = NULL;

    ogs_assert(sess);
    ogs_list_for_each(&sess->bearer_list, bearer)
        if (ebi == bearer->ebi) return bearer;

    return NULL;
}

sgwc_bearer_t *sgwc_bearer_find_by_ue_ebi(sgwc_ue_t *sgwc_ue, uint8_t ebi)
{
    sgwc_sess_t *sess = NULL;
    sgwc_bearer_t *bearer = NULL;
    
    ogs_assert(sgwc_ue);
    ogs_list_for_each(&sgwc_ue->sess_list, sess) {
        ogs_list_for_each(&sess->bearer_list, bearer) {
            if (ebi == bearer->ebi) return bearer;
        }
    }

    return NULL;
}

sgwc_bearer_t *sgwc_default_bearer_in_sess(sgwc_sess_t *sess)
{
    return sgwc_bearer_first(sess);
}

sgwc_bearer_t *sgwc_bearer_first(sgwc_sess_t *sess)
{
    ogs_assert(sess);
    return ogs_list_first(&sess->bearer_list);
}

sgwc_bearer_t *sgwc_bearer_next(sgwc_bearer_t *bearer)
{
    ogs_assert(bearer);
    return ogs_list_next(bearer);
}

sgwc_tunnel_t *sgwc_tunnel_add(sgwc_bearer_t *bearer, uint8_t interface_type)
{
    sgwc_tunnel_t *tunnel = NULL;

    ogs_assert(bearer);

    ogs_pool_alloc(&sgwc_tunnel_pool, &tunnel);
    ogs_assert(tunnel);
    memset(tunnel, 0, sizeof *tunnel);

    tunnel->interface_type = interface_type;
    tunnel->local_teid = ogs_pool_index(&sgwc_tunnel_pool, tunnel);
    ogs_assert(tunnel->local_teid > 0 &&
            tunnel->local_teid <= ogs_config()->pool.tunnel);

    tunnel->bearer = bearer;

    ogs_list_add(&bearer->tunnel_list, tunnel);

    return tunnel;
}

int sgwc_tunnel_remove(sgwc_tunnel_t *tunnel)
{
    ogs_assert(tunnel);
    ogs_assert(tunnel->bearer);

    ogs_list_remove(&tunnel->bearer->tunnel_list, tunnel);
    ogs_pool_free(&sgwc_tunnel_pool, tunnel);

    return OGS_OK;
}

void sgwc_tunnel_remove_all(sgwc_bearer_t *bearer)
{
    sgwc_tunnel_t *tunnel = NULL, *next_tunnel = NULL;

    ogs_assert(bearer);
    ogs_list_for_each_safe(&bearer->tunnel_list, next_tunnel, tunnel)
        sgwc_tunnel_remove(tunnel);
}

sgwc_tunnel_t *sgwc_tunnel_find_by_teid(uint32_t teid)
{
    return ogs_pool_find(&sgwc_tunnel_pool, teid);
}

sgwc_tunnel_t *sgwc_tunnel_find_by_interface_type(
        sgwc_bearer_t *bearer, uint8_t interface_type)
{
    sgwc_tunnel_t *tunnel = NULL;

    ogs_assert(bearer);

    tunnel = sgwc_tunnel_first(bearer);
    while (tunnel) {
        if (tunnel->interface_type == interface_type) {
            return tunnel;
        }

        tunnel = sgwc_tunnel_next(tunnel);
    }

    return NULL;
}

sgwc_tunnel_t *sgwc_s1u_tunnel_in_bearer(sgwc_bearer_t *bearer)
{
    ogs_assert(bearer);
    return sgwc_tunnel_find_by_interface_type(
            bearer, OGS_GTP_F_TEID_S1_U_SGW_GTP_U);
}
sgwc_tunnel_t *sgwc_s5u_tunnel_in_bearer(sgwc_bearer_t *bearer)
{
    ogs_assert(bearer);
    return sgwc_tunnel_find_by_interface_type(
            bearer, OGS_GTP_F_TEID_S5_S8_SGW_GTP_U);
}

sgwc_tunnel_t *sgwc_tunnel_first(sgwc_bearer_t *bearer)
{
    ogs_assert(bearer);
    return ogs_list_first(&bearer->tunnel_list);
}

sgwc_tunnel_t *sgwc_tunnel_next(sgwc_tunnel_t *tunnel)
{
    ogs_assert(tunnel);
    return ogs_list_next(tunnel);
}
