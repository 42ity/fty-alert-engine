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
#include <fty_proto.h>

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

typedef struct
{
    fty_proto_t* alert_msg;
    uint64_t     last_notification;
    uint64_t     last_received;
    fty_proto_t* related_asset;
} s_alert_cache;

///  Create a new fty_alert_actions
fty_alert_actions_t* fty_alert_actions_new();

///  Destroy the fty_alert_actions
void fty_alert_actions_destroy(fty_alert_actions_t** self_p);

///  Main actor function for actions module
void fty_alert_actions(zsock_t* pipe, void* args);

uint64_t get_alert_interval(s_alert_cache* alert_cache, uint64_t override_time = 0);
s_alert_cache* new_alert_cache_item(fty_alert_actions_t* self, fty_proto_t* msg);
void delete_alert_cache_item(void* c);
void s_handle_stream_deliver(fty_alert_actions_t* self, zmsg_t** msg_p, const char* subject);
