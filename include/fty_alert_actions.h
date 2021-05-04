/*  =========================================================================
    fty_alert_actions - Actor performing actions on alert (sending notifications)

    Copyright (C) 2014 - 2020 Eaton

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
    =========================================================================
*/
#pragma once

#include <malamute.h>

typedef struct _fty_alert_actions_t
{
    mlm_client_t* client;
    mlm_client_t* requestreply_client;
    zpoller_t*    requestreply_poller;
    zhash_t*      alerts_cache;
    zhash_t*      assets_cache;
    char*         name;
    char*         requestreply_name;
    bool          integration_test;
    uint64_t      notification_override;
    uint64_t      requestreply_timeout;
} fty_alert_actions_t;

//  @interface
//  Create a new fty_alert_actions
fty_alert_actions_t* fty_alert_actions_new(void);

//  Destroy the fty_alert_actions
void fty_alert_actions_destroy(fty_alert_actions_t** self_p);

//  Main actor function for actions module
void fty_alert_actions(zsock_t* pipe, void* args);

//  Self test of this class
void fty_alert_actions_test(bool verbose);

//  @end
