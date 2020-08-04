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

#include "gtp-path.h"

void sgwu_state_initial(ogs_fsm_t *s, sgwu_event_t *e)
{
    sgwu_sm_debug(e);

    ogs_assert(s);

    OGS_FSM_TRAN(s, &sgwu_state_operational);
}

void sgwu_state_final(ogs_fsm_t *s, sgwu_event_t *e)
{
    sgwu_sm_debug(e);

    ogs_assert(s);
}

void sgwu_state_operational(ogs_fsm_t *s, sgwu_event_t *e)
{
    int rv;
    sgwu_bearer_t *bearer = NULL;

    sgwu_sm_debug(e);

    ogs_assert(s);

    switch (e->id) {
    case OGS_FSM_ENTRY_SIG:
        rv = sgwu_gtp_open();
        if (rv != OGS_OK) {
            ogs_error("Can't establish SGW path");
            break;
        }
        break;
    case OGS_FSM_EXIT_SIG:
        sgwu_gtp_close();
        break;
    case SGWU_EVT_LO_DLDATA_NOTI:
        ogs_assert(e);

        bearer = e->bearer;
        ogs_assert(bearer);

#if 0
        sgwu_s11_handle_lo_dldata_notification(bearer);
#endif
        break;
    default:
        ogs_error("No handler for event %s", sgwu_event_get_name(e));
        break;
    }
}
