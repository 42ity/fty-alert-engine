/*  =========================================================================
    fty_alert_actions - Actor performing actions on alert (sending notifications)

    Copyright (C) 2014 - 2017 Eaton                                        
                                                                           
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

/*
@header
    fty_alert_actions - Actor performing actions on alert (sending notifications)
@discuss
@end
*/

#include "fty_alert_engine_classes.h"

#define EMAIL_ACTION            "EMAIL"
#define SMS_ACTION              "SMS"
#define EMAIL_SMS_ACTION        "EMAIL/SMS"
#define GPO_ACTION              "GPO_INTERACTION"
#define EMAIL_ACTION_VALUE      1
#define SMS_ACTION_VALUE        0

#define GPO_STATE_OPEN          "open"
#define GPO_STATE_CLOSE         "close"

#define FTY_EMAIL_AGENT_ADDRESS         "fty-email"
#define FTY_ASSET_AGENT_ADDRESS         "asset-agent"
#define FTY_SENSOR_GPIO_AGENT_ADDRESS   "fty-email"


//  Some stuff for testing purposes
//  to access test variables other than testing, use corresponding macro
#define TEST_VARS \
    zlist_t *testing_recv = NULL; \
    int testing_send = 0; \
    char *testing_uuid = NULL;
    char *testing_subject = NULL;
#ifdef __GNUC__
    #define unlikely(x) __builtin_expect(0 != x, 0)
#else
    #define unlikely(x) (0 != x)
#endif
#define mlm_client_recv(...) \
    (unlikely(testing) ? ((zmsg_t *)zlist_pop(testing_recv)) : mlm_client_recv(__VA_ARGS__))
#define mlm_client_sendtox(...) \
    (unlikely(testing) ? (testing_send) : mlm_client_sendtox(__VA_ARGS__))
#define mlm_client_sendto(...)  \
    (unlikely(testing) ? (testing_send) : mlm_client_sendto(__VA_ARGS__))
#define zuuid_str_canonical(...) \
    (unlikely(testing) ? (testing_uuid) : zuuid_str_canonical(__VA_ARGS__))
#define mlm_client_subject(...) \
    (unlikely(testing) ? (testing_subject) : mlm_client_subject(__VA_ARGS__))
#define CLEAN_RECV { \
        zmsg_t *l = (zmsg_t *) zlist_first(testing_recv); \
        while (NULL != l) { \
            zmsg_destroy(&l); \
            l = (zmsg_t *) zlist_next(testing_recv); \
        } \
        zlist_destroy(&testing_recv); \
    }
#define INIT_RECV { \
        testing_recv = zlist_new(); \
    }
#define MSG_TO_RECV(x) { \
        zlist_append(testing_recv, x); \
    }
#define SET_SEND(x) { \
        testing_send = x; \
    }
#define SET_UUID(x) { \
        testing_uuid = x; \
    }
#define GET_UUID \
    (testing_uuid)
#define SET_SUBJECT(x) { \
        testing_subject = x; \
    }
int testing = 0;
TEST_VARS


char verbose = 0;
static const std::map <std::pair <std::string, uint8_t>, uint32_t> times = {
    { {"CRITICAL", 1}, 5  * 60},
    { {"CRITICAL", 2}, 15 * 60},
    { {"CRITICAL", 3}, 15 * 60},
    { {"CRITICAL", 4}, 15 * 60},
    { {"CRITICAL", 5}, 15 * 60},
    { {"WARNING", 1}, 1 * 60 * 60},
    { {"WARNING", 2}, 4 * 60 * 60},
    { {"WARNING", 3}, 4 * 60 * 60},
    { {"WARNING", 4}, 4 * 60 * 60},
    { {"WARNING", 5}, 4 * 60 * 60},
    { {"INFO", 1}, 8 * 60 * 60},
    { {"INFO", 2}, 24 * 60 * 60},
    { {"INFO", 3}, 24 * 60 * 60},
    { {"INFO", 4}, 24 * 60 * 60},
    { {"INFO", 5}, 24 * 60 * 60}
};


//  Structure of our class

struct _fty_alert_actions_t {
    mlm_client_t    *client;
    zhash_t         *alerts_cache;
    zhash_t         *assets_cache;
    char            *name;
};

typedef struct {
    fty_proto_t *alert_msg;
    uint64_t    last_notification;
    fty_proto_t *related_asset;
} s_alert_cache;


// Forward declaration for function sanity
static void s_handle_stream_deliver_alert (fty_alert_actions_t *, fty_proto_t **, const char *);
static void s_handle_stream_deliver_asset (fty_alert_actions_t *, fty_proto_t **, const char *);


//  --------------------------------------------------------------------------
//  Fty proto destroy wrapper for freefn
void fty_proto_destroy_wrapper (void *x) {
    fty_proto_destroy ((fty_proto_t **) &x);
}

//  --------------------------------------------------------------------------
//  Create a new fty_alert_actions

fty_alert_actions_t *
fty_alert_actions_new (void)
{
    zsys_debug("fty_alert_actions: fty_alert_actions_new called");
    fty_alert_actions_t *self = (fty_alert_actions_t *) zmalloc (sizeof (fty_alert_actions_t));
    assert (self);
    //  Initialize class properties here
    self->client = mlm_client_new ();
    assert (self->client);
    self->alerts_cache = zhash_new ();
    assert (self->alerts_cache);
    self->assets_cache = zhash_new ();
    assert (self->assets_cache);
    return self;
}


//  --------------------------------------------------------------------------
//  Destroy the fty_alert_actions

void
fty_alert_actions_destroy (fty_alert_actions_t **self_p)
{
    zsys_debug("fty_alert_actions: fty_alert_actions_destroy called");
    assert (self_p);
    if (*self_p) {
        fty_alert_actions_t *self = *self_p;
        //  Free class properties here
        //  Free object itself
        if (NULL != self->client) {
            mlm_client_destroy (&self->client);
        }
        if (NULL != self->alerts_cache) {
            zhash_destroy (&self->alerts_cache);
        }
        if (NULL != self->assets_cache) {
            zhash_destroy (&self->assets_cache);
        }
        free (self);
        *self_p = NULL;
    }
}


//  --------------------------------------------------------------------------
//  Calculate alert interval for asset based on severity and priority

uint64_t
get_alert_interval(s_alert_cache *alert_cache)
{
    zsys_debug("fty_alert_actions: get_alert_interval called");
    std::string severity = fty_proto_severity(alert_cache->alert_msg);
    uint8_t priority = (uint8_t) fty_proto_aux_number(alert_cache->related_asset, "priority", 0);
    std::pair <std::string, uint8_t> key = {severity, priority};
    auto it = times.find(key);
    if (it != times.end()) {
        return (*it).second;
    } else {
        return 0;
    }
}


//  --------------------------------------------------------------------------
//  Create new cache object

s_alert_cache *
new_alert_cache_item(fty_alert_actions_t *self, fty_proto_t *msg)
{
    zsys_debug("fty_alert_actions: new_alert_cache_item called");
    assert(self);
    assert(msg);
    assert(fty_proto_name(msg));
    s_alert_cache *c = (s_alert_cache *) malloc(sizeof(s_alert_cache));
    c->alert_msg = msg;
    c->last_notification = zclock_mono ();
    c->related_asset = (fty_proto_t *) zhash_lookup(self->assets_cache, fty_proto_name(msg));
    if (NULL == c->related_asset) {
        // we don't know an asset we receieved alert about, ask fty-asset about it
        zsys_debug ("fty_alert_actions: ask ASSET AGENT for ASSET_DETAIL about %s", fty_proto_name(msg));
        zuuid_t *uuid = zuuid_new ();
        mlm_client_sendtox (self->client, FTY_ASSET_AGENT_ADDRESS, "ASSET_DETAIL", "GET",
                zuuid_str_canonical (uuid), fty_proto_name(msg), NULL);
        zmsg_t *reply_msg = mlm_client_recv (self->client);
        if (reply_msg) {
            char *rcv_uuid = zmsg_popstr (reply_msg);
            if (0 == strcmp (rcv_uuid, zuuid_str_canonical (uuid)) && fty_proto_is (reply_msg)) {
                zsys_debug("fty_alert_actions: receieved alert for unknown asset, asked for it and was successful.");
                fty_proto_t *reply_proto_msg = fty_proto_decode (&reply_msg);
                s_handle_stream_deliver_asset (self, &reply_proto_msg, mlm_client_subject (self->client));
                c->related_asset = reply_proto_msg;
            }
            else {
                zsys_warning("fty_alert_actions: receieved alert for unknown asset, ignoring.");
                zmsg_destroy(&reply_msg);
                fty_proto_destroy(&msg);
                free(c);
                c = NULL;
            }
            zstr_free(&rcv_uuid);
        }
        else {
            zsys_warning("fty_alert_actions: no response from ASSET AGENT, ignoring this alert.");
            zmsg_destroy(&reply_msg);
            fty_proto_destroy(&msg);
            free(c);
            c = NULL;
        }
        zuuid_destroy (&uuid);
    } else {
        zsys_debug("fty_alert_actions: found related asset.");
    }
    return c;
}


//  --------------------------------------------------------------------------
//  Destroy cache object

void
delete_alert_cache_item(void *c)
{
    zsys_debug("fty_alert_actions: delete_alert_cache_item called");
    fty_proto_destroy (&((s_alert_cache *)c)->alert_msg);
    free(c);
}


//  --------------------------------------------------------------------------
//  Send email containing alert message

void
send_email(fty_alert_actions_t *self, s_alert_cache *alert_item, char action_email)
{
    zsys_debug("fty_alert_actions: sending SENDMAIL_ALERT for %s", fty_proto_name(alert_item->alert_msg));
    fty_proto_t *alert_dup = fty_proto_dup(alert_item->alert_msg);
    zmsg_t *email_msg = fty_proto_encode(&alert_dup);
    zuuid_t *uuid = zuuid_new ();
    const char *sname = fty_proto_ext_string(alert_item->related_asset, "name", "");
    if (EMAIL_ACTION_VALUE == action_email) {
        const char *contact_email = fty_proto_ext_string(alert_item->related_asset, "contact_email", "");
        zmsg_pushstr (email_msg, contact_email);
    } else {
        const char *contact_sms = fty_proto_ext_string(alert_item->related_asset, "contact_sms", "");
        zmsg_pushstr (email_msg, contact_sms);
    }
    const char *priority = fty_proto_aux_string(alert_item->related_asset, "priority", "");
    zmsg_pushstr (email_msg, sname);
    zmsg_pushstr (email_msg, priority);
    zmsg_pushstr (email_msg, zuuid_str_canonical (uuid));
    int rv = mlm_client_sendto (self->client, FTY_EMAIL_AGENT_ADDRESS, "SENDMAIL_ALERT", NULL, 5000, &email_msg);
    if ( rv != 0) {
        zsys_error ("fty_alert_actions: cannot send SENDMAIL_ALERT message");
        zuuid_destroy (&uuid);
        zmsg_destroy (&email_msg);
        return;
    }
    zmsg_t *reply_msg = mlm_client_recv (self->client);
    if (reply_msg) {
        char *rcv_uuid = zmsg_popstr (reply_msg);
        if (0 == strcmp (rcv_uuid, zuuid_str_canonical (uuid))) {
            char *cmd = zmsg_popstr (reply_msg);
            if (0 == strcmp(cmd, "OK")) {
                zsys_error ("fty_alert_actions: SENDMAIL_ALERT successful");
            } else {
                char *cause = zmsg_popstr (reply_msg);
                zsys_error ("fty_alert_actions: SENDMAIL_ALERT failed due to %s", cause);
                zstr_free(&cause);
            }
            zstr_free(&cmd);
        } else {
            zsys_error ("fty_alert_actions: received invalid reply on SENDMAIL_ALERT message");
        }
        zstr_free(&rcv_uuid);
    }
    zuuid_destroy (&uuid);
}


//  --------------------------------------------------------------------------
//  Send message to sensor-gpoi to set gpo to desired state

void
send_gpo_action(fty_alert_actions_t *self, char *gpo_iname, char *gpo_state)
{
    zsys_debug("fty_alert_actions: sending GPO_INTERACTION for %s", gpo_iname);
    int rv = mlm_client_sendtox (self->client, FTY_SENSOR_GPIO_AGENT_ADDRESS, "GPO_INTERACTION", gpo_iname, gpo_state, NULL);
    if ( rv != 0) {
        zsys_error ("fty_alert_actions: cannot send GPO_INTERACTION message");
        return;
    }
    zmsg_t *reply_msg = mlm_client_recv (self->client);
    if (reply_msg) {
        char *cmd = zmsg_popstr (reply_msg);
        if (0 == strcmp(cmd, "OK")) {
            zsys_error ("fty_alert_actions: SENDMAIL_ALERT successful");
        } else {
            char *cause = zmsg_popstr (reply_msg);
            zsys_error ("fty_alert_actions: SENDMAIL_ALERT failed due to %s", cause);
            zstr_free(&cause);
        }
        zstr_free(&cmd);
    }
}


//  --------------------------------------------------------------------------
//  Send active actions for an alert that is sent for the first time
//  Emails, smses and gpos are handled here

void
action_alert(fty_alert_actions_t *self, s_alert_cache *alert_item)
{
    zsys_debug("fty_alert_actions: action_alert called");
    const char *action = (const char *) fty_proto_action_first(alert_item->alert_msg);
    while (NULL != action) {
        char *action_dup = strdup(action);
        char *action_what = strtok(action_dup, ":");
        if (NULL == action_what) {
            zsys_warning("fty_alert_actions: alert action miss command");
            action = (const char *) zlist_next(fty_proto_action(alert_item->alert_msg));
            free(action_dup);
            continue;
        }
        char *tmp = strtok(NULL, ":");
        if (streq (action_what, EMAIL_ACTION)) {
            if (NULL == tmp) { // sanity check
                send_email(self, alert_item, EMAIL_ACTION_VALUE);
            } else {
                zsys_warning("fty_alert_actions: unexpected parameter received for email action");
            }
        }
        else if (streq (action_what, SMS_ACTION)) {
            if (NULL == tmp) { // sanity check
                send_email(self, alert_item, SMS_ACTION_VALUE);
            } else {
                zsys_warning("fty_alert_actions: unexpected parameter received for sms action");
            }
        }
        else if (streq (action_what, GPO_ACTION)) {
            char *gpo_iname = tmp; // asset iname
            if (NULL == gpo_iname) {
                zsys_warning("fty_alert_actions: GPO_ACTION miss asset iname");
                action = (const char *) zlist_next(fty_proto_action(alert_item->alert_msg));
                free(action_dup);
                continue;
            }
            char *gpo_state = strtok(NULL, ":"); // required state
            if (NULL == gpo_state) {
                zsys_warning("fty_alert_actions: GPO_ACTION miss required state");
                action = (const char *) zlist_next(fty_proto_action(alert_item->alert_msg));
                free(action_dup);
                continue;
            }
            tmp = strtok(NULL, ":"); // required state
            if (NULL == tmp) { // sanity check
                send_gpo_action(self, gpo_iname, gpo_state);
            } else {
                zsys_warning("fty_alert_actions: unexpected parameter received for gpo_interaction action");
            }
        }
        else {
            zsys_warning("fty_alert_actions: unsupported alert action");
        }
        free(action_dup);
        action = (const char *) fty_proto_action_next(alert_item->alert_msg);
    }
}


//  --------------------------------------------------------------------------
//  Send active actions for an alert that is periodically repeated
//  Only emails and smses are handled here

void
action_alert_repeat(fty_alert_actions_t *self, s_alert_cache *alert_item)
{
    zsys_debug("fty_alert_actions: action_alert_repeat called");
    if (streq (fty_proto_state (alert_item->alert_msg), "ACK-PAUSE") ||
            streq (fty_proto_state (alert_item->alert_msg), "ACK-IGNORE") ||
            streq (fty_proto_state (alert_item->alert_msg), "ACK-SILENCE")) {
        zsys_debug("fty_alert_actions: alert on %s acked, won't repeat alerts", fty_proto_name(alert_item->alert_msg));
        return;
    }
    const char *action = (const char *) fty_proto_action_first(alert_item->alert_msg);
    while (NULL != action) {
        char *action_dup = strdup(action);
        char *action_what = strtok(action_dup, ":");
        if (NULL == action_what) {
            zsys_warning("fty_alert_actions: alert action miss command");
            action = (const char *) zlist_next(fty_proto_action(alert_item->alert_msg));
            free(action_dup);
            continue;
        }
        char *tmp = strtok(NULL, ":");
        if (streq (action_what, EMAIL_ACTION)) {
            if (NULL == tmp) { // sanity check
                send_email(self, alert_item, EMAIL_ACTION_VALUE);
            } else {
                zsys_warning("fty_alert_actions: unexpected parameter received for email action");
            }
        }
        else if (streq (action_what, SMS_ACTION)) {
            if (NULL == tmp) { // sanity check
                send_email(self, alert_item, SMS_ACTION_VALUE);
            } else {
                zsys_warning("fty_alert_actions: unexpected parameter received for sms action");
            }
        }
        else if (streq (action_what, GPO_ACTION)) {
            // happily ignored
        }
        else {
            zsys_warning("fty_alert_actions: unsupported alert action");
        }
        free(action_dup);
        action = (const char *) fty_proto_action_next(alert_item->alert_msg);
    }
}


//  --------------------------------------------------------------------------
//  Send resolve actions for an alert
//  Only gpos are handled here

void
action_resolve(fty_alert_actions_t *self, s_alert_cache *alert_item)
{
    zsys_debug("fty_alert_actions: action_resolve called");
    const char *action = (const char *) fty_proto_action_first(alert_item->alert_msg);
    while (NULL != action) {
        char *action_dup = strdup(action);
        char *action_what = strtok(action_dup, ":");
        if (NULL == action_what) {
            zsys_warning("fty_alert_actions: alert action miss command");
            action = (const char *) zlist_next(fty_proto_action(alert_item->alert_msg));
            free(action_dup);
            continue;
        }
        char *tmp = strtok(NULL, ":");
        if (streq (action_what, EMAIL_ACTION)) {
            // happily ignored
        }
        else if (streq (action_what, SMS_ACTION)) {
            // happily ignored
        }
        else if (streq (action_what, GPO_ACTION)) {
            char *gpo_iname = tmp; // asset iname
            if (NULL == gpo_iname) {
                zsys_warning("fty_alert_actions: GPO_ACTION miss asset iname");
                action = (const char *) zlist_next(fty_proto_action(alert_item->alert_msg));
                free(action_dup);
                continue;
            }
            char *gpo_state = strtok(NULL, ":"); // required state
            if (NULL == gpo_state) {
                zsys_warning("fty_alert_actions: GPO_ACTION miss required state");
                action = (const char *) zlist_next(fty_proto_action(alert_item->alert_msg));
                free(action_dup);
                continue;
            }
            // for resolve opposite values are sent
            if (0 == strcmp(gpo_state, GPO_STATE_OPEN)) {
                gpo_state = (char *) GPO_STATE_CLOSE;
            } else {
                gpo_state = (char *) GPO_STATE_OPEN;
            }
            tmp = strtok(NULL, ":"); // required state
            if (NULL == tmp) { // sanity check
                send_gpo_action(self, gpo_iname, gpo_state);
            } else {
                zsys_warning("fty_alert_actions: unexpected parameter received for gpo_interaction action");
            }
        }
        else {
            zsys_warning("fty_alert_actions: unsupported alert action");
        }
        free(action_dup);
        action = (const char *) fty_proto_action_next(alert_item->alert_msg);
    }
}


//  --------------------------------------------------------------------------
//  Check for timed out alerts, resolve them and delete them

void
check_timed_out_alerts(fty_alert_actions_t *self)
{
    zsys_debug("fty_alert_actions: check_timed_out_alerts called");
    s_alert_cache *it = (s_alert_cache *) zhash_first(self->alerts_cache);
    uint64_t now = zclock_mono ();
    while (NULL != it) {
        if (fty_proto_time(it->alert_msg) + fty_proto_ttl(it->alert_msg) < now) {
            zsys_debug("fty_alert_actions: found timed out alert from %s", fty_proto_name(it->alert_msg));
            action_resolve(self, it);
            zhash_delete(self->alerts_cache, zhash_cursor(self->alerts_cache));
        }
        it = (s_alert_cache *) zhash_next(self->alerts_cache);
    }
    zsys_debug("fty_alert_actions: check_timed_out_alerts check done");
}


//  --------------------------------------------------------------------------
//  Resend alerts periodically based on times table - severity and priority

void
check_alerts_and_send_if_needed(fty_alert_actions_t *self)
{
    zsys_debug("fty_alert_actions: check_alerts_and_send_if_needed called");
    s_alert_cache *it = (s_alert_cache *) zhash_first(self->alerts_cache);
    uint64_t now = zclock_mono ();
    while (NULL != it) {
        uint64_t notification_delay = get_alert_interval(it);
        if (0 != notification_delay && (it->last_notification + notification_delay < now)) {
            action_alert_repeat(self, it);
        }
        it = (s_alert_cache *) zhash_next(self->alerts_cache);
    }
    zsys_debug("fty_alert_actions: check_alerts_and_send_if_needed check done");
}


//  --------------------------------------------------------------------------
//  Handle incoming alerts through stream

static void
s_handle_stream_deliver_alert (fty_alert_actions_t *self, fty_proto_t **alert_p, const char *subject)
{
    zsys_debug("fty_alert_actions: s_handle_stream_deliver_alert called");
    assert (self);
    assert (alert_p);
    assert (subject);
    fty_proto_t *alert = *alert_p;
    if (!alert || fty_proto_id (alert) != FTY_PROTO_ALERT) {
        fty_proto_destroy (&alert);
        zsys_warning ("fty_alert_actions: Message not FTY_PROTO_ALERT.");
        return;
    }
    s_alert_cache *search;
    const char *rule = fty_proto_rule (alert);
    search = (s_alert_cache *) zhash_lookup(self->alerts_cache, rule);
    if (streq (fty_proto_state (alert), "ACTIVE") || streq (fty_proto_state (alert), "ACK-WIP") ||
            streq (fty_proto_state (alert), "ACK-PAUSE") || streq (fty_proto_state (alert), "ACK-IGNORE") ||
            streq (fty_proto_state (alert), "ACK-SILENCE")) {
        zsys_debug("fty_alert_actions: receieved ACTIVE alarm with subject %s", subject);
        if (NULL == search) {
            // create new alert object in cache
            zsys_debug("fty_alert_actions: new alarm, add it to database");
            search = new_alert_cache_item (self, alert);
            if (NULL == search) {
                fty_proto_destroy (alert_p);
                return;
            }
            zhash_insert (self->alerts_cache, rule, search);
            zhash_freefn (self->alerts_cache, rule, delete_alert_cache_item);
            action_alert(self, search);
        } else {
            zsys_debug("fty_alert_actions: known alarm, check for changes");
            char changed = 0;
            // little more complicated, update cache, alert on changes
            if (!streq(fty_proto_severity(search->alert_msg), fty_proto_severity(alert)) ||
                    !streq(fty_proto_description(search->alert_msg), fty_proto_description(alert))) {
                changed = 1;
            }
            const char *action1 = fty_proto_action_first(search->alert_msg);
            const char *action2 = fty_proto_action_first(alert);
            while (NULL != action1 && NULL != action2) {
                if (!streq(action1, action2)) {
                    changed = 1;
                    break;
                }
                action1 = fty_proto_action_next(search->alert_msg);
                action2 = fty_proto_action_next(alert);
            }
            if (NULL != action1 || NULL != action2) {
                changed = 1;
            }
            fty_proto_destroy(&search->alert_msg);
            search->alert_msg = alert;
            if (1 == changed) {
                zsys_debug("fty_alert_actions: known alarm resolved as updated, sending notifications");
                action_alert(self, search);
            }
        }
    }
    else if (streq (fty_proto_state (alert), "RESOLVED")) {
        zsys_debug("fty_alert_actions: receieved RESOLVED alarm with subject %s", subject);
        if (NULL != search) {
            action_resolve(self, search);
            zsys_debug("fty_alert_actions: receieved RESOLVED alarm resolved");
            zhash_delete(self->alerts_cache, rule);
        }
        // we don't care about alerts that are resolved and not stored - were never active
        fty_proto_destroy (alert_p);
    }
    else {
        fty_proto_destroy (alert_p);
        zsys_warning ("fty_alert_actions: Message state not ACTIVE or RESOLVED. Skipping it.");
    }
    return;
}


//  --------------------------------------------------------------------------
//  Handle incoming assets through stream

static void
s_handle_stream_deliver_asset (fty_alert_actions_t *self, fty_proto_t **asset_p, const char *subject)
{
    zsys_debug("fty_alert_actions: s_handle_stream_deliver_asset called");
    assert (self);
    assert (asset_p);
    assert (subject);
    fty_proto_t *asset = *asset_p;
    if (!asset || fty_proto_id (asset) != FTY_PROTO_ASSET) {
        fty_proto_destroy (&asset);
        zsys_warning ("fty_alert_actions: Message not FTY_PROTO_ASSET.");
        return;
    }
    const char *operation = fty_proto_operation (asset);
    const char *assetname = fty_proto_name (asset);

    if (streq (operation, "delete")) {
        zsys_debug("fty_alert_actions: received delete for asset %s", assetname);
        fty_proto_t *item = (fty_proto_t *)zhash_lookup (self->assets_cache, assetname);
        if (NULL != item) {
            s_alert_cache *it = (s_alert_cache *) zhash_first(self->alerts_cache);
            if (NULL != it)
                zsys_debug("fty_alert_actions: %d had active alarms, resolving them", assetname);
            while (NULL != it) {
                if (it->related_asset == item) {
                    // delete all alerts related to deleted asset
                    action_resolve(self, it);
                    zhash_delete(self->alerts_cache, zhash_cursor(self->alerts_cache));
                }
                it = (s_alert_cache *) zhash_next(self->alerts_cache);
            }
            zhash_delete (self->assets_cache, assetname);
        }
        fty_proto_destroy (asset_p);
    }
    else if (streq (operation, "update")) {
        zsys_debug("fty_alert_actions: received update for asset %s", assetname);
        zhash_update(self->assets_cache, assetname, asset);
        zhash_freefn(self->assets_cache, assetname, fty_proto_destroy_wrapper);
    }
    else {
        zsys_debug("fty_alert_actions: not an update or delete operation for this message");
        fty_proto_destroy (asset_p);
    }
}


//  --------------------------------------------------------------------------
//  Handle incoming alerts through stream

static void
s_handle_stream_deliver (fty_alert_actions_t *self, zmsg_t** msg_p, const char *subject)
{
    zsys_debug("fty_alert_actions: s_handle_stream_deliver called");
    assert (self);
    assert (msg_p);
    fty_proto_t *proto_msg = fty_proto_decode (msg_p);
    if (NULL != proto_msg && fty_proto_id (proto_msg) == FTY_PROTO_ALERT) {
        s_handle_stream_deliver_alert(self, &proto_msg, subject);
    }
    else if (NULL != proto_msg && fty_proto_id (proto_msg) == FTY_PROTO_ASSET) {
        s_handle_stream_deliver_asset(self, &proto_msg, subject);
    }
    else {
        zsys_warning ("fty_alert_actions: Message not FTY_PROTO_ALERT nor FTY_PROTO_ASSET, ignoring.");
        fty_proto_destroy (&proto_msg);
    }
    return;
}


//  --------------------------------------------------------------------------
//  Handle incoming alerts through pipe

static int
s_handle_pipe_deliver (fty_alert_actions_t *self, zmsg_t** msg_p)
{
    zsys_debug("fty_alert_actions: s_handle_pipe_deliver called");
    zmsg_t *msg = *msg_p;
    char *cmd = zmsg_popstr (msg);

    if (streq (cmd, "$TERM")) {
        zsys_debug ("fty_alert_actions: $TERM received");
        zstr_free (&cmd);
        zmsg_destroy (&msg);
        return -1;
    }
    else
    if (streq (cmd, "VERBOSE")) {
        zsys_debug ("fty_alert_actions: VERBOSE received");
        verbose = 1;
    }
    else
    if (streq (cmd, "CONNECT")) {
        zsys_debug ("fty_alert_actions: CONNECT received");
        char* endpoint = zmsg_popstr (msg);
        int rv = mlm_client_connect (self->client, endpoint, 1000, self->name);
        if (rv == -1)
            zsys_error ("fty_alert_actions: can't connect to malamute endpoint '%s'", endpoint);
        zstr_free (&endpoint);
    }
    else
    if (streq (cmd, "CONSUMER")) {
        zsys_debug ("fty_alert_actions: CONSUMER received");
        char* stream = zmsg_popstr (msg);
        char* pattern = zmsg_popstr (msg);
        int rv = mlm_client_set_consumer (self->client, stream, pattern);
        if (rv == -1)
            zsys_error ("fty_alert_actions: can't set consumer on stream '%s', '%s'", stream, pattern);
        zstr_free (&pattern);
        zstr_free (&stream);
    }
    else if (streq(cmd, "ASKFORASSETS")) {
        zsys_debug ("fty_alert_actions: asking for assets");
        zmsg_t *republish = zmsg_new ();
        int rv = mlm_client_sendto (self->client, FTY_ASSET_AGENT_ADDRESS, "REPUBLISH", NULL, 5000, &republish);
        if ( rv != 0) {
            zsys_error ("fty_alert_actions: can't send REPUBLISH message");
        }
    }
    zstr_free (&cmd);
    zmsg_destroy (&msg);
    return 0;
}


//  --------------------------------------------------------------------------
//  fty_alert_actions actor function

void
fty_alert_actions (zsock_t *pipe, void* args)
{
    zsys_debug("fty_alert_actions: fty_alert_actions called");
    fty_alert_actions_t *self = fty_alert_actions_new ();
    assert(self);
    self->name = (char*) args;
    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (self->client), NULL);
    assert (poller);
    uint64_t timeout = 1000 * 60 * 1; // check every minute
    zsock_signal (pipe, 0);
    zmsg_t *msg = NULL;
    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, timeout);
        if (which == NULL) {
            if (zpoller_terminated (poller) || zsys_interrupted) {
                zsys_warning ("fty_alert_actions: zpoller_terminated () or zsys_interrupted. Shutting down.");
                break;
            }
            if (zpoller_expired (poller)) {
                zsys_debug("fty_alert_actions: poller timeout expired");
                check_timed_out_alerts(self);
                check_alerts_and_send_if_needed(self);
            }
            continue;
        }
        // pipe messages
        if (which == pipe) {
            msg = zmsg_recv (pipe);
            if (0 == s_handle_pipe_deliver(self, &msg)) {
                continue;
            } else {
                break;
            }
        }
        msg = mlm_client_recv (self->client);
        // stream messages - receieve ASSETS and ALERTS
        if (is_fty_proto (msg)) {
            s_handle_stream_deliver (self, &msg, mlm_client_subject (self->client));
            continue;
        }
        // all other messages should be ignored
        zsys_debug("fty_alert_actions: received message through '%s' from '%s' with subject '%s' that is ignored",
                mlm_client_address (self->client),
                mlm_client_sender (self->client),
                mlm_client_subject (self->client));
    }
    zpoller_destroy (&poller);
    fty_alert_actions_destroy (&self);
}


//  --------------------------------------------------------------------------
//  Self test of this class

// If your selftest reads SCMed fixture data, please keep it in
// src/selftest-ro; if your test creates filesystem objects, please
// do so under src/selftest-rw.
// The following pattern is suggested for C selftest code:
//    char *filename = NULL;
//    filename = zsys_sprintf ("%s/%s", SELFTEST_DIR_RO, "mytemplate.file");
//    assert (filename);
//    ... use the "filename" for I/O ...
//    zstr_free (&filename);
// This way the same "filename" variable can be reused for many subtests.
#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

void
fty_alert_actions_test (bool verbose)
{
    printf (" * fty_alert_actions: ");
    testing = 1;
    SET_SUBJECT((char *)"testing");

    //  @selftest
    // test 1, simple create/destroy self test
    {
    zsys_debug("fty_alert_actions: test 1");
    fty_alert_actions_t *self = fty_alert_actions_new ();
    assert (self);
    fty_alert_actions_destroy (&self);
    }
    // test 2, check alert interval calculation
    {
    zsys_debug("fty_alert_actions: test 2");
    s_alert_cache *cache = (s_alert_cache *) malloc(sizeof(s_alert_cache));
    cache->alert_msg = fty_proto_new(FTY_PROTO_ALERT);
    cache->related_asset = fty_proto_new(FTY_PROTO_ASSET);
    
    fty_proto_set_severity(cache->alert_msg, "CRITICAL");
    fty_proto_aux_insert(cache->related_asset, "priority", "%u", (unsigned int)1);
    assert(5  * 60 == get_alert_interval(cache));

    fty_proto_set_severity(cache->alert_msg, "WARNING");
    fty_proto_aux_insert(cache->related_asset, "priority", "%u", (unsigned int)1);
    assert(1 * 60 * 60 == get_alert_interval(cache));
    
    fty_proto_set_severity(cache->alert_msg, "INFO");
    fty_proto_aux_insert(cache->related_asset, "priority", "%u", (unsigned int)1);
    assert(8 * 60 * 60 == get_alert_interval(cache));

    fty_proto_set_severity(cache->alert_msg, "CRITICAL");
    fty_proto_aux_insert(cache->related_asset, "priority", "%u", (unsigned int)3);
    assert(15 * 60 == get_alert_interval(cache));

    fty_proto_set_severity(cache->alert_msg, "WARNING");
    fty_proto_aux_insert(cache->related_asset, "priority", "%u", (unsigned int)3);
    assert(4 * 60 * 60 == get_alert_interval(cache));

    fty_proto_set_severity(cache->alert_msg, "INFO");
    fty_proto_aux_insert(cache->related_asset, "priority", "%u", (unsigned int)3);
    assert(24 * 60 * 60 == get_alert_interval(cache));

    fty_proto_set_severity(cache->alert_msg, "CRITICAL");
    fty_proto_aux_insert(cache->related_asset, "priority", "%u", (unsigned int)5);
    assert(15 * 60 == get_alert_interval(cache));

    fty_proto_set_severity(cache->alert_msg, "WARNING");
    fty_proto_aux_insert(cache->related_asset, "priority", "%u", (unsigned int)5);
    assert(4 * 60 * 60 == get_alert_interval(cache));

    fty_proto_set_severity(cache->alert_msg, "INFO");
    fty_proto_aux_insert(cache->related_asset, "priority", "%u", (unsigned int)5);
    assert(24 * 60 * 60 == get_alert_interval(cache));

    fty_proto_destroy(&cache->alert_msg);
    fty_proto_destroy(&cache->related_asset);
    free(cache);
    }
    // test 3, simple create/destroy cache item test without need to send ASSET_DETAILS
    {
    zsys_debug("fty_alert_actions: test 3");
    fty_alert_actions_t *self = fty_alert_actions_new ();
    assert (self);
    fty_proto_t *asset = fty_proto_new(FTY_PROTO_ASSET);
    assert (asset);
    zhash_insert(self->assets_cache, "myasset-1", asset);
    fty_proto_t *msg = fty_proto_new(FTY_PROTO_ALERT);
    assert (msg);
    fty_proto_set_name(msg, "myasset-1");

    s_alert_cache *cache = new_alert_cache_item(self, msg);
    assert(cache);
    delete_alert_cache_item(cache);

    fty_proto_destroy(&asset);
    fty_alert_actions_destroy (&self);
    }
    // test 4, simple create/destroy cache item test with need to send ASSET_DETAILS
    {
    zsys_debug("fty_alert_actions: test 4");
    SET_UUID((char *)"uuid-test");
    zhash_t *aux = zhash_new();
    zhash_t *ext = zhash_new();
    zmsg_t *resp_msg = fty_proto_encode_asset(aux, "myasset-2", "update", ext);
    zmsg_pushstr(resp_msg, GET_UUID);
    assert(resp_msg);
    INIT_RECV;
    MSG_TO_RECV(resp_msg);
    SET_SEND(0);
    fty_alert_actions_t *self = fty_alert_actions_new ();
    assert (self);
    fty_proto_t *msg = fty_proto_new(FTY_PROTO_ALERT);
    assert (msg);
    fty_proto_set_name(msg, "myasset-2");

    s_alert_cache *cache = new_alert_cache_item(self, msg);
    assert(cache);
    delete_alert_cache_item(cache);

    fty_alert_actions_destroy (&self);
    zhash_destroy(&aux);
    zhash_destroy(&ext);
    CLEAN_RECV;
    }
    //  @end
    printf ("OK\n");
}
