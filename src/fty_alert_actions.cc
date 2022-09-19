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

#include "fty_alert_actions.h"
#include <fty_log.h>
#include <fty_proto.h>

#define TEST_ASSETS "ASSETS-TEST"
#define TEST_ALERTS "ALERTS-TEST"

#define FTY_EMAIL_AGENT_ADDRESS_TEST       "fty-email-test"
#define FTY_SENSOR_GPIO_AGENT_ADDRESS_TEST "fty-sensor-gpio-test"

#define EMAIL_ACTION       "EMAIL"
#define SMS_ACTION         "SMS"
#define EMAIL_SMS_ACTION   "EMAIL/SMS"
#define GPO_ACTION         "GPO_INTERACTION"
#define EMAIL_ACTION_VALUE 1
#define SMS_ACTION_VALUE   0

#define GPO_STATE_OPEN  "open"
#define GPO_STATE_CLOSE "close"

#define FTY_EMAIL_AGENT_ADDRESS       "fty-email"
#define FTY_ASSET_AGENT_ADDRESS       "asset-agent"
#define FTY_SENSOR_GPIO_AGENT_ADDRESS "fty-sensor-gpio"

//  Some stuff for testing purposes
//  to access test variables other than testing, use corresponding macro
#if !defined(MLM_MAKE_VERSION) || !defined(MLM_VERSION)
#error "MLM_MAKE_VERSION macro not defined"
#endif
#if (MLM_MAKE_VERSION(1, 1, 0) != MLM_VERSION) && (MLM_MAKE_VERSION(1, 2, 0) != MLM_VERSION)
/* Hotfix: malamute-1.1 final was released Oct 2020, after holding the pending
 * version number for several years; now the upstream source is dubbed 1.2 with
 * no changes as of Feb 2021. So for a quick build fix, check above also trusts
 * "1.2.0" although the code is allowed to not compile if API does change over
 * time (should not do so in an incompatible manner across minor releases...)
 */
#error "MLM version has changed, please check function signatures are matching for testing framework"
#endif


static const std::map<std::pair<std::string, uint8_t>, uint32_t> times = {
    //                 h *  m *  s *   ms
    {{"CRITICAL", 1},       5 * 60 * 1000}, // =  5m
    {{"CRITICAL", 2},      15 * 60 * 1000}, // = 15m
    {{"CRITICAL", 3},      15 * 60 * 1000}, // = 15m
    {{"CRITICAL", 4},      15 * 60 * 1000}, // = 15m
    {{"CRITICAL", 5},      15 * 60 * 1000}, // = 15m
    {{"WARNING",  1},      60 * 60 * 1000}, // =  1h
    {{"WARNING",  2},  4 * 60 * 60 * 1000}, // =  4h
    {{"WARNING",  3},  4 * 60 * 60 * 1000}, // =  4h
    {{"WARNING",  4},  4 * 60 * 60 * 1000}, // =  4h
    {{"WARNING",  5},  4 * 60 * 60 * 1000}, // =  4h
    {{"INFO",     1},  8 * 60 * 60 * 1000}, // =  8h
    {{"INFO",     2}, 24 * 60 * 60 * 1000}, // = 24h
    {{"INFO",     3}, 24 * 60 * 60 * 1000}, // = 24h
    {{"INFO",     4}, 24 * 60 * 60 * 1000}, // = 24h
    {{"INFO",     5}, 24 * 60 * 60 * 1000}  // = 24h
};


//  Structure of our class

/* struct _fty_alert_actions_t
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
}; */

// Forward declaration for function sanity
static void s_handle_stream_deliver_alert(fty_alert_actions_t*, fty_proto_t**, const char*);
static void s_handle_stream_deliver_asset(fty_alert_actions_t*, fty_proto_t**, const char*);


//  --------------------------------------------------------------------------
//  fty_proto_t destroy for freefn
static void delete_fty_proto_item(void* item)
{
    fty_proto_t* p = static_cast<fty_proto_t*>(item);
    if (!p) return;

    fty_proto_destroy(&p);
}

//  --------------------------------------------------------------------------
//  s_alert_cache destroy for freefn
void delete_alert_cache_item(void* item)
{
    s_alert_cache* c = static_cast<s_alert_cache*>(item);
    if (!c) return;

    fty_proto_destroy(&c->alert_msg);
    memset(c, 0, sizeof(*c));
    free(c);
}

//  --------------------------------------------------------------------------
//  Create a new fty_alert_actions_t

fty_alert_actions_t* fty_alert_actions_new()
{
    fty_alert_actions_t* self = static_cast<fty_alert_actions_t*>(zmalloc(sizeof(fty_alert_actions_t)));
    assert(self);
    memset(self, 0, sizeof(*self));

    //  Initialize class properties here
    self->client = mlm_client_new();
    assert(self->client);
    self->requestreply_client = mlm_client_new();
    assert(self->requestreply_client);
    self->requestreply_poller = zpoller_new(mlm_client_msgpipe(self->requestreply_client), NULL);
    assert(self->requestreply_poller);
    self->alerts_cache = zhash_new();
    assert(self->alerts_cache);
    self->assets_cache = zhash_new();
    assert(self->assets_cache);
    self->integration_test      = false;
    self->notification_override = 0;
    self->name                  = NULL;
    self->requestreply_name     = NULL;

    return self;
}


//  --------------------------------------------------------------------------
//  Destroy the fty_alert_actions

void fty_alert_actions_destroy(fty_alert_actions_t** self_p)
{
    if (self_p && *self_p) {
        fty_alert_actions_t* self = *self_p;

        mlm_client_destroy(&self->client);
        zpoller_destroy(&self->requestreply_poller);
        mlm_client_destroy(&self->requestreply_client);
        zhash_destroy(&self->alerts_cache);
        zhash_destroy(&self->assets_cache);
        zstr_free(&self->requestreply_name);
        zstr_free(&self->name);

        free(self);
        *self_p = NULL;
    }
}


//  --------------------------------------------------------------------------
//  Calculate alert interval for asset based on severity and priority

uint64_t get_alert_interval(s_alert_cache* alert_cache, uint64_t override_time)
{
    if (override_time > 0) {
        return override_time;
    }

    const char* severity = fty_proto_severity(alert_cache->alert_msg);
    if (!severity) {
        log_warning("alert severity is not defined");
        return 0;
    }

    if (!alert_cache->related_asset) {
        log_warning("alert related_asset is not defined");
        return 0;
    }
    uint8_t priority = static_cast<uint8_t>(fty_proto_aux_number(alert_cache->related_asset, "priority", 0));

    std::pair<std::string, uint8_t> key = {severity, priority};
    auto it = times.find(key);

    if (it != times.end()) {
        return it->second;
    }

    log_warning("alert severity/priority pair not found (%s, %d)", severity, priority);
    return 0;
}


//  --------------------------------------------------------------------------
//  Create new s_alert_cache object
//  Caller must destroy msg if NULL is returned
s_alert_cache* new_alert_cache_item(fty_alert_actions_t* self, fty_proto_t* msg)
{
    assert(self);
    assert(msg);

    if ((fty_proto_id(msg) != FTY_PROTO_ALERT) || !fty_proto_name(msg)) {
        log_warning("ALERT proto msg malformed");
        return NULL;
    }

    log_debug("search asset %s", fty_proto_name(msg));

    s_alert_cache* c = static_cast<s_alert_cache*>(zmalloc(sizeof(*c)));
    if (!c) {
        log_error("s_alert_cache alloc. failed");
        return NULL;
    }

    memset(c, 0, sizeof(*c));
    c->last_notification = static_cast<uint64_t>(zclock_mono());
    c->last_received     = c->last_notification;

    c->related_asset = static_cast<fty_proto_t*>(zhash_lookup(self->assets_cache, fty_proto_name(msg)));
    if (!c->related_asset && !self->integration_test)
    {
        // we don't know an asset we received alert about, ask fty-asset about it
        log_debug("request %s (ASSET_DETAIL %s)", FTY_ASSET_AGENT_ADDRESS, fty_proto_name(msg));

        zuuid_t* uuid = zuuid_new();
        mlm_client_sendtox(self->requestreply_client, FTY_ASSET_AGENT_ADDRESS, "ASSET_DETAIL", "GET",
            zuuid_str_canonical(uuid), fty_proto_name(msg), NULL);

        void* which = zpoller_wait(self->requestreply_poller, static_cast<int>(self->requestreply_timeout));
        if (which == NULL) {
            log_warning("no response from %s (ASSET_DETAIL %s)", FTY_ASSET_AGENT_ADDRESS, fty_proto_name(msg));
            free(c);
            c = NULL; // msg will be destroyed by caller
        }
        else {
            zmsg_t* reply_msg = mlm_client_recv(self->requestreply_client);
            char* rcv_uuid  = zmsg_popstr(reply_msg);
            if (streq(rcv_uuid, zuuid_str_canonical(uuid)) && fty_proto_is(reply_msg)) {
                log_debug("receive response from %s (ASSET_DETAIL %s)", FTY_ASSET_AGENT_ADDRESS, fty_proto_name(msg));

                fty_proto_t* reply_proto_msg = fty_proto_decode(&reply_msg);
                fty_proto_set_operation(reply_proto_msg, "%s", FTY_PROTO_ASSET_OP_UPDATE);
                s_handle_stream_deliver_asset(self, &reply_proto_msg, mlm_client_subject(self->client));
                c->related_asset = static_cast<fty_proto_t*>(zhash_lookup(self->assets_cache, fty_proto_name(msg)));
                if (!c->related_asset) {
                    log_warning("related_asset not found after assets_cache update (%s)", fty_proto_name(msg));
                }
            }
            else {
                log_warning("received alert for unknown asset, ignoring.");
                free(c);
                c = NULL; // msg will be destroyed by caller
            }
            zstr_free(&rcv_uuid);
            zmsg_destroy(&reply_msg);
        }
        zuuid_destroy(&uuid);
    }

    if (c) {
        c->alert_msg = msg; // msg owned by alert_cache
    }

    return c;
}

//  --------------------------------------------------------------------------
//  Send email containing alert message

void send_email(fty_alert_actions_t* self, s_alert_cache* alert_item, char action_email)
{
    log_debug("send_email() %s", fty_proto_rule(alert_item->alert_msg));

    if (!alert_item->related_asset) {
        log_error("send_email(): alert related_asset is NULL");
        return;
    }

    const char* subject = NULL;
    const char* contact = NULL;
    switch (action_email) {
        case EMAIL_ACTION_VALUE:
            subject = "SENDMAIL_ALERT";
            contact = fty_proto_ext_string(alert_item->related_asset, "contact_email", NULL);
            break;
        case SMS_ACTION_VALUE:
            subject = "SENDSMS_ALERT";
            contact = fty_proto_ext_string(alert_item->related_asset, "contact_sms", NULL);
            break;
        default:
            log_error("Unknown action (%d)", static_cast<int>(action_email));
            return;
    }

    if (!contact || (strlen(contact) == 0)) {
        log_debug("%s contact is empty (no mail sent)", fty_proto_name(alert_item->alert_msg));
        return;
    }

    const char* sname = fty_proto_ext_string(alert_item->related_asset, "name", "");
    const char* priority = fty_proto_aux_string(alert_item->related_asset, "priority", "");
    zuuid_t* uuid = zuuid_new();
    const char* sent_uuid = zuuid_str_canonical(uuid);

    zmsg_t* msg = NULL;
    {
        fty_proto_t* dup = fty_proto_dup(alert_item->alert_msg);
        msg = fty_proto_encode(&dup);
        fty_proto_destroy(&dup);
    }

    zmsg_pushstr(msg, contact);
    zmsg_pushstr(msg, sname);
    zmsg_pushstr(msg, priority);
    zmsg_pushstr(msg, sent_uuid);

    const char* address = (self->integration_test) ? FTY_EMAIL_AGENT_ADDRESS_TEST : FTY_EMAIL_AGENT_ADDRESS;
    const int timeout_ms = 5000;

    log_info("request %s/%s (rule: %s, contact: %s)",
        address, subject, fty_proto_rule(alert_item->alert_msg), contact);
    //zmsg_print(msg);

    int rv = mlm_client_sendto(self->requestreply_client, address, subject, NULL, timeout_ms, &msg);
    zmsg_destroy(&msg);
    if (rv != 0) {
        log_error("send %s/%s message failed (rv: %d)", address, subject, rv);
        zuuid_destroy(&uuid);
        return;
    }

    void* which = zpoller_wait(self->requestreply_poller, static_cast<int>(self->requestreply_timeout));
    if (which == NULL) {
        log_error("no reply received on %s/%s request", address, subject);
    }
    else {
        msg = mlm_client_recv(self->requestreply_client);
        char* rcv_uuid = zmsg_popstr(msg);

        if (streq(rcv_uuid, sent_uuid)) {
            char* status = zmsg_popstr(msg);
            char* reason = zmsg_popstr(msg);

            if (streq(status, "OK")) {
                log_debug("received %s on %s/%s request", status, address, subject);
            }
            else {
                log_error("received %s (%s) on %s/%s request", status, reason, address, subject);
            }
            zstr_free(&reason);
            zstr_free(&status);
        }
        else {
            log_error("received nomatch uuid reply on %s/%s request (uuid: %s, expected: %s)",
                address, subject, rcv_uuid, sent_uuid);
        }

        zstr_free(&rcv_uuid);
    }

    zmsg_destroy(&msg);
    zuuid_destroy(&uuid);
}


//  --------------------------------------------------------------------------
//  Send message to sensor-gpoi to set gpo to desired state

void send_gpo_action(fty_alert_actions_t* self, char* gpo_iname, char* gpo_state)
{
    const char* address = (self->integration_test) ? FTY_SENSOR_GPIO_AGENT_ADDRESS_TEST : FTY_SENSOR_GPIO_AGENT_ADDRESS;

    log_debug("sending %s/GPO_INTERACTION/%s/%s", address, gpo_iname, gpo_state);

    zuuid_t* zuuid = zuuid_new();

    int rv = mlm_client_sendtox(
        self->requestreply_client, address, "GPO_INTERACTION", zuuid_str_canonical(zuuid), gpo_iname, gpo_state, NULL);

    if (rv != 0) {
        log_error("cannot send %s/GPO_INTERACTION/%s message", address, gpo_iname);
    }
    else {
        int timeout_ms = static_cast<int>(self->requestreply_timeout);
        void* which = zpoller_wait(self->requestreply_poller, timeout_ms);
        if (which == NULL) {
            log_error("reply timedout (%d ms) on %s/GPO_INTERACTION/%s message", timeout_ms, address, gpo_iname);
        }
        else {
            zmsg_t* reply_msg = mlm_client_recv(self->requestreply_client);
            char*   zuuid_str = zmsg_popstr(reply_msg);
            if (streq(zuuid_str, zuuid_str_canonical(zuuid))) {
                char* status = zmsg_popstr(reply_msg);
                if (streq(status, "OK")) {
                    log_debug("GPO_INTERACTION successful");
                }
                else {
                    char* reason = zmsg_popstr(reply_msg);
                    log_error("%s/GPO_INTERACTION/%s failed due to %s/%s", address, gpo_iname, status, reason);
                    zstr_free(&reason);
                }
                zstr_free(&status);
            }
            else {
                log_error("received mismatch uuid reply on %s/GPO_INTERACTION/%s message", address, gpo_iname);
            }
            zstr_free(&zuuid_str);
            zmsg_destroy(&reply_msg);
        }
    }

    zuuid_destroy(&zuuid);
}


//  --------------------------------------------------------------------------
//  Send active actions for an alert that is sent for the first time
//  Emails, smses and gpos are handled here

void action_alert(fty_alert_actions_t* self, s_alert_cache* alert_item)
{
    log_debug("action_alert called for %s", fty_proto_rule(alert_item->alert_msg));

    const char* action = fty_proto_action_first(alert_item->alert_msg);
    if (!action) {
        log_debug("no action defined");
    }
    while (action) {
        char* action_dup  = strdup(action);
        char* action_what = strtok(action_dup, ":");
        log_debug("action: %s", action);

        if (NULL == action_what) {
            log_warning("alert action misses command");
            action = static_cast<const char*>(zlist_next(fty_proto_action(alert_item->alert_msg)));
            free(action_dup);
            continue;
        }

        char* tmp = strtok(NULL, ":");
        if (streq(action_what, EMAIL_ACTION)) {
            if (NULL == tmp) { // sanity check
                send_email(self, alert_item, EMAIL_ACTION_VALUE);
            } else {
                log_warning("unexpected parameter received for email action");
            }
        } else if (streq(action_what, SMS_ACTION)) {
            if (NULL == tmp) { // sanity check
                send_email(self, alert_item, SMS_ACTION_VALUE);
            } else {
                log_warning("unexpected parameter received for sms action");
            }
        } else if (streq(action_what, GPO_ACTION)) {
            char* gpo_iname = tmp; // asset iname
            if (NULL == gpo_iname) {
                log_warning("GPO_ACTION misses asset iname");
                action = static_cast<const char*>(zlist_next(fty_proto_action(alert_item->alert_msg)));
                free(action_dup);
                continue;
            }
            char* gpo_state = strtok(NULL, ":"); // required state
            if (NULL == gpo_state) {
                log_warning("GPO_ACTION miss required state");
                action = static_cast<const char*>(zlist_next(fty_proto_action(alert_item->alert_msg)));
                free(action_dup);
                continue;
            }
            tmp = strtok(NULL, ":"); // required state
            if (NULL == tmp) {       // sanity check
                send_gpo_action(self, gpo_iname, gpo_state);
            } else {
                log_warning("unexpected parameter received for gpo_interaction action");
            }
        } else {
            log_warning("unsupported alert action : %s ", action_what);
        }

        free(action_dup);
        action = fty_proto_action_next(alert_item->alert_msg);
    }
}


//  --------------------------------------------------------------------------
//  Send active actions for an alert that is periodically repeated
//  Only emails and smses are handled here

void action_alert_repeat(fty_alert_actions_t* self, s_alert_cache* alert_item)
{
    log_debug("action_alert_repeat called for %s", fty_proto_rule(alert_item->alert_msg));

    if (streq(fty_proto_state(alert_item->alert_msg), "ACK-PAUSE") ||
        streq(fty_proto_state(alert_item->alert_msg), "ACK-IGNORE") ||
        streq(fty_proto_state(alert_item->alert_msg), "ACK-SILENCE")) {

        log_debug("alert on %s acked, won't repeat alerts (state: %s)",
            fty_proto_name(alert_item->alert_msg), fty_proto_state(alert_item->alert_msg));
        return;
    }

    const char* action = fty_proto_action_first(alert_item->alert_msg);
    if (!action) {
        log_debug("no action defined");
    }
    while (action) {
        char* action_dup  = strdup(action);
        char* action_what = strtok(action_dup, ":");
        log_debug("action: %s", action);

        if (!action_what) {
            log_warning("alert action miss command");
        }
        else {
            char* tmp = strtok(NULL, ":");
            if (streq(action_what, EMAIL_ACTION)) {
                if (!tmp) { // sanity check
                    send_email(self, alert_item, EMAIL_ACTION_VALUE);
                } else {
                    log_warning("unexpected parameter received for email action (tmp: %s)", tmp);
                }
            }
            else if (streq(action_what, SMS_ACTION)) {
                if (!tmp) { // sanity check
                    send_email(self, alert_item, SMS_ACTION_VALUE);
                } else {
                    log_warning("unexpected parameter received for sms action (tmp: %s)", tmp);
                }
            }
            else if (streq(action_what, GPO_ACTION)) {
                // happily ignored
            }
            else {
                log_warning("unsupported alert action: %s", action_what);
            }
        }

        free(action_dup);
        action = fty_proto_action_next(alert_item->alert_msg);
    }
}


//  --------------------------------------------------------------------------
//  Send resolve actions for an alert
//  Only gpos are handled here

void action_resolve(fty_alert_actions_t* self, s_alert_cache* alert_item)
{
    log_debug("action_resolve called for %s", fty_proto_name(alert_item->alert_msg));
    const char* action = fty_proto_action_first(alert_item->alert_msg);
    while (NULL != action) {
        char* action_dup  = strdup(action);
        char* action_what = strtok(action_dup, ":");
        if (NULL == action_what) {
            log_warning("alert action miss command");
            action = static_cast<const char*>(zlist_next(fty_proto_action(alert_item->alert_msg)));
            free(action_dup);
            continue;
        }
        char* tmp = strtok(NULL, ":");
        if (streq(action_what, EMAIL_ACTION)) {
            // happily ignored
        } else if (streq(action_what, SMS_ACTION)) {
            // happily ignored
        } else if (streq(action_what, GPO_ACTION)) {
            char* gpo_iname = tmp; // asset iname
            if (NULL == gpo_iname) {
                log_warning("GPO_ACTION miss asset iname");
                action = static_cast<const char*>(zlist_next(fty_proto_action(alert_item->alert_msg)));
                free(action_dup);
                continue;
            }
            char* gpo_state = strtok(NULL, ":"); // required state
            if (NULL == gpo_state) {
                log_warning("GPO_ACTION miss required state");
                action = static_cast<const char*>(zlist_next(fty_proto_action(alert_item->alert_msg)));
                free(action_dup);
                continue;
            }
            // for resolve opposite values are sent
            if (0 == strcmp(gpo_state, GPO_STATE_OPEN)) {
                strcpy(gpo_state, GPO_STATE_CLOSE);
            } else {
                strcpy(gpo_state, GPO_STATE_OPEN);
            }
            tmp = strtok(NULL, ":"); // required state
            if (NULL == tmp) {       // sanity check
                send_gpo_action(self, gpo_iname, gpo_state);
            } else {
                log_warning("unexpected parameter received for gpo_interaction action");
            }
        } else {
            log_warning("unsupported alert action : %s", action_what);
        }
        free(action_dup);
        action = fty_proto_action_next(alert_item->alert_msg);
    }
}


//  --------------------------------------------------------------------------
//  Check for timed out alerts, resolve them and delete them

void check_timed_out_alerts(fty_alert_actions_t* self)
{
    log_debug("check_timed_out_alerts");

    uint64_t now = static_cast<uint64_t>(zclock_mono());

    for (void* item = zhash_first(self->alerts_cache); item; item = zhash_next(self->alerts_cache))
    {
        s_alert_cache* it = static_cast<s_alert_cache*>(item);
        uint64_t alert_ttl_ms = uint64_t(fty_proto_ttl(it->alert_msg)) * 1000;

        if ((it->last_received + alert_ttl_ms) <= now) {
            log_debug("found timed out alert from %s - resolving it", fty_proto_name(it->alert_msg));
            action_resolve(self, it);
            zhash_delete(self->alerts_cache, zhash_cursor(self->alerts_cache));
        }
    }
}


//  --------------------------------------------------------------------------
//  Resend alerts periodically based on times table - severity and priority

void check_alerts_and_send_if_needed(fty_alert_actions_t* self)
{
    log_debug("check_alerts_and_send_if_needed (alerts_cache size: %zu)", zhash_size(self->alerts_cache));

    uint64_t now = static_cast<uint64_t>(zclock_mono());

    for (void* item = zhash_first(self->alerts_cache); item; item = zhash_next(self->alerts_cache))
    {
        s_alert_cache* it = static_cast<s_alert_cache*>(item);

        uint64_t notification_delay = get_alert_interval(it, self->notification_override);
        if ((notification_delay != 0)
            && ((it->last_notification + notification_delay) <= now)
        ){
            log_debug("%s action started", fty_proto_rule(it->alert_msg));

            it->last_notification = static_cast<uint64_t>(zclock_mono());
            action_alert_repeat(self, it);
        }
        else {
            uint64_t remaining = it->last_notification + notification_delay - now;

            log_debug("%s action waiting (delay: %zu s, remaining: %zu s)",
                fty_proto_rule(it->alert_msg), notification_delay/1000, remaining/1000);
        }
    }
}


//  --------------------------------------------------------------------------
//  Handle incoming alerts through stream

static void s_handle_stream_deliver_alert(fty_alert_actions_t* self, fty_proto_t** alert_p, const char* subject)
{
    assert(self);
    assert(alert_p);
    assert(subject);

    fty_proto_t* alert = *alert_p;
    if (!alert || (fty_proto_id(alert) != FTY_PROTO_ALERT)) {
        fty_proto_destroy(alert_p);
        log_warning("Message not FTY_PROTO_ALERT.");
        return;
    }

    const char* rule = fty_proto_rule(alert);
    s_alert_cache* search = static_cast<s_alert_cache*>(zhash_lookup(self->alerts_cache, rule));

    // ignore new alert with no action defined
    if (!search && !fty_proto_action_first(alert)) {
        log_debug("ignore alert %s (no action)", subject);
        fty_proto_destroy(alert_p);
        return;
    }

    if (streq(fty_proto_state(alert), "ACTIVE")
        || streq(fty_proto_state(alert), "ACK-WIP")
        || streq(fty_proto_state(alert), "ACK-PAUSE")
        || streq(fty_proto_state(alert), "ACK-IGNORE")
        || streq(fty_proto_state(alert), "ACK-SILENCE")
    ){
        if (!search) {
            // create new alert object in cache
            log_debug("new alarm deliver %s (state: %s)", subject, fty_proto_state(alert));
            search = new_alert_cache_item(self, alert);
            if (!search) {
                log_error("failed to create %s in alerts_cache", subject);
                fty_proto_destroy(alert_p);
                return;
            }
            *alert_p = NULL; // alert is now owned by search

            zhash_insert(self->alerts_cache, rule, search);
            zhash_freefn(self->alerts_cache, rule, delete_alert_cache_item);

            action_alert(self, search);
        }
        else { // update alert
            log_debug("update alarm deliver %s (state: %s)", subject, fty_proto_state(alert));

            search->last_received = static_cast<uint64_t>(zclock_mono());

            // little more complicated, update cache, alert on changes
            bool changed = false;

            if (streq(fty_proto_state(search->alert_msg), "ACTIVE")
                && (streq(fty_proto_state(alert), "ACK-WIP")
                    || streq(fty_proto_state(alert), "ACK-PAUSE")
                    || streq(fty_proto_state(alert), "ACK-IGNORE")
                    || streq(fty_proto_state(alert), "ACK-SILENCE"))
            ){
                changed = true;
            }

            if (!changed && !streq(fty_proto_severity(search->alert_msg), fty_proto_severity(alert))) {
                changed = true;
            }

            if (!changed && !streq(fty_proto_description(search->alert_msg), fty_proto_description(alert))) {
                changed = true;
            }

            if (!changed) {
                const char* action1 = fty_proto_action_first(search->alert_msg);
                const char* action2 = fty_proto_action_first(alert);
                while (action1 && action2) {
                    if (!streq(action1, action2)) {
                        changed = true;
                        break;
                    }
                    action1 = fty_proto_action_next(search->alert_msg);
                    action2 = fty_proto_action_next(alert);
                }
                if (action1 || action2) {
                    changed = true;
                }
            }

            if (changed) {
                // simple workaround to handle alerts for assets changed during alert being active
                log_debug("known alarm resolved as updated, resolving previous alert");
                action_resolve(self, search);
            }

            // update alert in alerts_cache
            fty_proto_destroy(&search->alert_msg);
            search->alert_msg = alert;
            *alert_p = NULL; // alert is now owned by search

            if (changed) {
                log_debug("known alarm resolved as updated, sending notifications");
                action_alert(self, search);
            }
        }
    }
    else if (streq(fty_proto_state(alert), "RESOLVED")) {
        if (search) {
            search->last_received = static_cast<uint64_t>(zclock_mono());
            action_resolve(self, search);
            log_debug("received RESOLVED alarm with subject %s resolved", subject);
            zhash_delete(self->alerts_cache, rule);
        }
        // we don't care about alerts that are resolved and not stored - were never active
        fty_proto_destroy(alert_p);
    }
    else {
        fty_proto_destroy(alert_p);
        log_warning("Message state not ACTIVE or RESOLVED. Skipping it.");
    }
}


//  --------------------------------------------------------------------------
//  Handle incoming assets through stream

static void s_handle_stream_deliver_asset(
    fty_alert_actions_t* self, fty_proto_t** asset_p, const char* subject)
{
    assert(self);
    assert(asset_p);
    assert(subject);

    fty_proto_t* asset = *asset_p;
    if (!asset || (fty_proto_id(asset) != FTY_PROTO_ASSET)) {
        log_warning("Message not FTY_PROTO_ASSET");
        fty_proto_destroy(asset_p);
        return;
    }

    const char* operation = fty_proto_operation(asset);
    const char* assetname = fty_proto_name(asset);

    if (streq(operation, FTY_PROTO_ASSET_OP_DELETE)
        || !streq(fty_proto_aux_string(asset, FTY_PROTO_ASSET_STATUS, "active"), "active")
    ){
        log_debug("recv delete/nonactive for asset %s", assetname);
        fty_proto_t* item = static_cast<fty_proto_t*>(zhash_lookup(self->assets_cache, assetname));
        if (item) {
            s_alert_cache* it = static_cast<s_alert_cache*>(zhash_first(self->alerts_cache));
            while (it) {
                if (it->related_asset == item) {
                    // delete all alerts related to deleted asset
                    action_resolve(self, it);
                    zhash_delete(self->alerts_cache, zhash_cursor(self->alerts_cache));
                }
                it = static_cast<s_alert_cache*>(zhash_next(self->alerts_cache));
            }
            zhash_delete(self->assets_cache, assetname);
        }
    }
    else if (streq(operation, FTY_PROTO_ASSET_OP_UPDATE)) {
        log_debug("recv update for asset %s", assetname);
        fty_proto_t* known = static_cast<fty_proto_t*>(zhash_lookup(self->assets_cache, assetname));
        if (known) { // asset exist in cache, update
            char changed = 0;

            if (!streq(fty_proto_ext_string(known, "contact_email", ""), fty_proto_ext_string(asset, "contact_email", ""))
                || !streq(fty_proto_ext_string(known, "contact_phone", ""), fty_proto_ext_string(asset, "contact_phone", ""))
            ){
                changed = 1;
            }

            if (changed) {
                // simple workaround to handle alerts for assets changed during alert being active
                log_debug("known asset was updated, resolving previous alert");
                s_alert_cache* it = static_cast<s_alert_cache*>(zhash_first(self->alerts_cache));
                while (it) {
                    if (it->related_asset == known) {
                        // just resolve, will be activated again
                        action_resolve(self, it);
                    }
                    it = static_cast<s_alert_cache*>(zhash_next(self->alerts_cache));
                }
            }

            zhash_t* tmp_ext = fty_proto_get_ext(asset);
            zhash_t* tmp_aux = fty_proto_get_aux(asset);
            fty_proto_set_ext(known, &tmp_ext);
            fty_proto_set_aux(known, &tmp_aux);

            if (changed) {
                log_debug("known asset was updated, sending notifications");
                s_alert_cache* it = static_cast<s_alert_cache*>(zhash_first(self->alerts_cache));
                while (it) {
                    if (it->related_asset == known) {
                        // force an alert since contact info changed
                        action_alert(self, it);
                    }
                    it = static_cast<s_alert_cache*>(zhash_next(self->alerts_cache));
                }
            }
        }
        else { // new asset, add it in assets_cache
            zhash_insert(self->assets_cache, assetname, asset);
            zhash_freefn(self->assets_cache, assetname, delete_fty_proto_item);
            *asset_p = NULL; // asset owned by assets_cache
        }
    }
    else {
        // ignore others
        // 'create' is skipped because each is followed by an 'update'
        // 'inventory' is skipped because it does not contain any info we need
    }

    fty_proto_destroy(asset_p);
}


//  --------------------------------------------------------------------------
//  Handle incoming alert/asset notifications through stream

void s_handle_stream_deliver(fty_alert_actions_t* self, zmsg_t** msg_p, const char* subject)
{
    assert(self);
    assert(msg_p);

    fty_proto_t* proto_msg = fty_proto_decode(msg_p);

    if (proto_msg && fty_proto_id(proto_msg) == FTY_PROTO_ALERT) {
        s_handle_stream_deliver_alert(self, &proto_msg, subject);
    }
    else if (proto_msg && fty_proto_id(proto_msg) == FTY_PROTO_ASSET) {
        s_handle_stream_deliver_asset(self, &proto_msg, subject);
    }
    else {
        log_warning("Message not FTY_PROTO_ALERT nor FTY_PROTO_ASSET, ignoring.");
        fty_proto_destroy(&proto_msg);
    }
}


//  --------------------------------------------------------------------------
//  Handle incoming alerts through pipe
//  Returns  -1 if $TERM received, else 0

static int s_handle_pipe_deliver(fty_alert_actions_t* self, zmsg_t** msg_p, uint64_t& timeout)
{
    assert(self);
    assert(msg_p);

    zmsg_t* msg = *msg_p;
    char*   cmd = zmsg_popstr(msg);
    log_debug("%s received", cmd);
    assert(cmd);

    if (streq(cmd, "$TERM")) {
        zstr_free(&cmd);
        zmsg_destroy(msg_p);
        return -1;
    }

    if (streq(cmd, "CONNECT")) {
        char* endpoint = zmsg_popstr(msg);
        int   rv       = mlm_client_connect(self->client, endpoint, 1000, self->name);
        if (rv == -1) {
            log_error("can't connect to malamute endpoint '%s'", endpoint);
        }
        rv = mlm_client_connect(self->requestreply_client, endpoint, 1000, self->requestreply_name);
        if (rv == -1)
            log_error("can't connect requestreply to malamute endpoint '%s'", endpoint);
        zstr_free(&endpoint);
    } else if (streq(cmd, "CONSUMER")) {
        char* stream           = zmsg_popstr(msg);
        char* pattern          = zmsg_popstr(msg);
        self->integration_test = streq(stream, TEST_ALERTS) || streq(stream, TEST_ASSETS);
        int   rv               = mlm_client_set_consumer(self->client, stream, pattern);
        if (rv == -1) {
            log_error("can't set consumer on stream '%s', '%s'", stream, pattern);
        }
        zstr_free(&pattern);
        zstr_free(&stream);
    } else if (streq(cmd, "ASKFORASSETS")) {
        log_debug("asking for assets");
        zmsg_t* republish = zmsg_new();
        int     rv = mlm_client_sendto(self->client, FTY_ASSET_AGENT_ADDRESS, "REPUBLISH", NULL, 5000, &republish);
        zmsg_destroy(&republish);
        if (rv != 0) {
            log_error("can't send REPUBLISH message");
        }
    } else if (streq(cmd, "TESTTIMEOUT")) {
        char* rcvd = zmsg_popstr(msg);
        log_debug("setting test timeout to received value (timeout: %s)", rcvd);
        uint64_t aux;
        if (rcvd && (sscanf(rcvd, "%" SCNu64, &aux) == 1)) {
            timeout = aux;
        }
        zstr_free(&rcvd);
    } else if (streq(cmd, "TESTCHECKINTERVAL")) {
        char* rcvd = zmsg_popstr(msg);
        log_debug("setting test interval for checks (rcvd: %s)", rcvd);
        uint64_t aux;
        if (rcvd && (sscanf(rcvd, "%" SCNu64, &aux) == 1)) {
            self->notification_override = aux;
        }
        zstr_free(&rcvd);
    }

    zstr_free(&cmd);
    zmsg_destroy(msg_p);
    return 0;
}


//  --------------------------------------------------------------------------
//  fty_alert_actions actor function

void fty_alert_actions(zsock_t* pipe, void* args)
{
    log_info("fty_alert_actions started");
    assert(args);

    fty_alert_actions_t* self = fty_alert_actions_new();
    assert(self);

    self->name                 = strdup(static_cast<char*>(args));
    self->requestreply_name    = zsys_sprintf("%s-sendmail", self->name);
    self->requestreply_timeout = 5000; //ms

    zpoller_t* poller = zpoller_new(pipe, mlm_client_msgpipe(self->client), NULL);
    assert(poller);

    zsock_signal(pipe, 0);

    zmsg_t*  msg         = NULL;
    uint64_t timeout     = 1000 * 10; // msg poll every 10 seconds
    uint64_t check_delay = 1000 * 60; // check every minute
    uint64_t last        = static_cast<uint64_t>(zclock_mono());

    while (!zsys_interrupted) {
        void* which = zpoller_wait(poller, static_cast<int>(timeout));

        uint64_t now = static_cast<uint64_t>(zclock_mono());
        if ((now - last) >= check_delay) {
            log_debug("performing periodic check");
            last = now;
            check_timed_out_alerts(self);
            check_alerts_and_send_if_needed(self);
        }

        if (which == NULL) {
            if (zpoller_terminated(poller) || zsys_interrupted) {
                log_warning("zpoller_terminated () or zsys_interrupted. Shutting down.");
                break;
            }
            continue;
        }

        // pipe messages
        if (which == pipe) {
            msg = zmsg_recv(pipe);
            if (s_handle_pipe_deliver(self, &msg, timeout) != 0) {
                break; //$TERM
            }
            continue;
        }

        msg = mlm_client_recv(self->client);
        // stream messages - receive ASSETS and ALERTS
        if (fty_proto_is(msg)) {
            s_handle_stream_deliver(self, &msg, mlm_client_subject(self->client));
            continue;
        }
        // all other messages should be ignored
        log_debug("received message through '%s' from '%s' with subject '%s' that is ignored",
            mlm_client_address(self->client), mlm_client_sender(self->client), mlm_client_subject(self->client));
        zmsg_destroy(&msg);
    }

    zpoller_destroy(&poller);
    fty_alert_actions_destroy(&self);

    log_info("fty_alert_actions ended");
}
