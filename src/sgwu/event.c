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

#include "event.h"
#include "context.h"

static OGS_POOL(pool, sgwu_event_t);

#define EVENT_POOL 32 /* FIXME : 32 */
void sgwu_event_init(void)
{
    ogs_pool_init(&pool, EVENT_POOL);

    sgwu_self()->queue = ogs_queue_create(EVENT_POOL);
    ogs_assert(sgwu_self()->queue);
    sgwu_self()->timer_mgr = ogs_timer_mgr_create();
    ogs_assert(sgwu_self()->timer_mgr);
    sgwu_self()->pollset = ogs_pollset_create();
    ogs_assert(sgwu_self()->pollset);
}

void sgwu_event_term(void)
{
    ogs_queue_term(sgwu_self()->queue);
    ogs_pollset_notify(sgwu_self()->pollset);
}

void sgwu_event_final(void)
{
    if (sgwu_self()->pollset)
        ogs_pollset_destroy(sgwu_self()->pollset);
    if (sgwu_self()->timer_mgr)
        ogs_timer_mgr_destroy(sgwu_self()->timer_mgr);
    if (sgwu_self()->queue)
        ogs_queue_destroy(sgwu_self()->queue);

    ogs_pool_final(&pool);
}

sgwu_event_t *sgwu_event_new(sgwu_event_e id)
{
    sgwu_event_t *e = NULL;

    ogs_pool_alloc(&pool, &e);
    ogs_assert(e);
    memset(e, 0, sizeof(*e));

    e->id = id;

    return e;
}

void sgwu_event_free(sgwu_event_t *e)
{
    ogs_assert(e);
    ogs_pool_free(&pool, e);
}

const char *sgwu_event_get_name(sgwu_event_t *e)
{
    if (e == NULL)
        return OGS_FSM_NAME_INIT_SIG;

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG: 
        return OGS_FSM_NAME_ENTRY_SIG;
    case OGS_FSM_EXIT_SIG: 
        return OGS_FSM_NAME_EXIT_SIG;

    case SGWU_EVT_SXA_MESSAGE:
        return "SGWU_EVT_SXA_MESSAGE";
    case SGWU_EVT_SXA_TIMER:
        return "SGWU_EVT_SXA_TIMER";
    case SGWU_EVT_SXA_NO_HEARTBEAT:
        return "SGWU_EVT_SXA_NO_HEARTBEAT";

    default: 
       break;
    }

    return "UNKNOWN_EVENT";
}
