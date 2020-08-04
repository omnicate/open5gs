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

#ifndef SGWC_EVENT_H
#define SGWC_EVENT_H

#include "ogs-core.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ogs_gtp_node_s ogs_gtp_node_t;
typedef struct sgwc_bearer_s sgwc_bearer_t;

typedef enum {
    SGW_EVT_BASE = OGS_FSM_USER_SIG,

    SGW_EVT_S11_MESSAGE,
    SGW_EVT_S5C_MESSAGE,

    SGW_EVT_LO_DLDATA_NOTI,

    SGW_EVT_TOP,

} sgwc_event_e;

typedef struct sgwc_event_s {
    int id;
    ogs_pkbuf_t *pkbuf;

    ogs_gtp_node_t *gnode;

    sgwc_bearer_t *bearer;
} sgwc_event_t;

void sgwc_event_init(void);
void sgwc_event_term(void);
void sgwc_event_final(void);

sgwc_event_t *sgwc_event_new(sgwc_event_e id);
void sgwc_event_free(sgwc_event_t *e);

const char *sgwc_event_get_name(sgwc_event_t *e);

#ifdef __cplusplus
}
#endif

#endif /* SGWC_EVENT_H */
