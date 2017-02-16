/*  =========================================================================
    fty_alert_engine_server - Actor evaluating rules

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
    fty_alert_engine_server - Actor evaluating rules
@discuss
@end
*/
#include <string.h>
#include <string>
#include <vector>
#include <sstream>
#include <malamute.h>
#include <fty_proto.h>
#include <math.h>
#include <functional>
#include <algorithm>

int agent_alert_verbose = 0;

#define zsys_debug1(...) \
    do { if (agent_alert_verbose) zsys_debug (__VA_ARGS__); } while (0);

#include "rule.h"
#include "normalrule.h"
#include "thresholdrulesimple.h"
#include "thresholdrulecomplex.h"
#include "regexrule.h"

#include "alertconfiguration.h"
#include "autoconfig.h"

#define METRICS_STREAM "METRICS"
#define RULES_SUBJECT "rfc-evaluator-rules"

#include "fty_alert_engine.h"
#include "fty_alert_engine_classes.h"

static void
list_rules(
    mlm_client_t *client,
    const char *type,
    const char *ruleclass,
    AlertConfiguration &ac)
{
    std::function<bool(const std::string& s)> filter_f;
    if (streq (type,"all")) {
        filter_f = [](const std::string& s) {return true; };
    }
    else if (streq (type,"threshold")) {
        filter_f = [](const std::string& s) {return s.compare ("threshold") == 0; };
    }
    else if (streq (type,"single")) {
        filter_f = [](const std::string& s) {return s.compare ("single") == 0; };
    }
    else if (streq (type,"pattern")) {
        filter_f = [](const std::string& s) {return s.compare ("pattern") == 0; };
    }
    else {
        //invalid type
        zsys_warning ("type '%s' is invalid", type);
        zmsg_t *reply = zmsg_new ();
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "INVALID_TYPE");
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        return;
    }

    std::string rclass;
    if (ruleclass) {
        rclass = ruleclass;
    }
    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "LIST");
    zmsg_addstr (reply, type);
    zmsg_addstr (reply, rclass.c_str ());
    // std::vector <
    //  std::pair <
    //      RulePtr,
    //      std::vector<PureAlert>
    //      >
    // >
    zsys_debug1 ("number of all rules = '%zu'", ac.size ());
    for (const auto &i: ac) {
        const auto& rule = i.first;
        if (! (filter_f (rule->whoami ()) && (rclass.empty() || rule->rule_class() == rclass)) ) {
            zsys_debug1 ("Skipping rule  = '%s' class '%s'", rule->name().c_str(), rule->rule_class().c_str());
            continue;
        }
        zsys_debug1 ("Adding rule  = '%s'", rule->name().c_str());
        zmsg_addstr (reply, rule->getJsonRule().c_str());
    }
    mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
}

static void
get_rule(
    mlm_client_t *client,
    const char *name,
    AlertConfiguration &ac)
{
    assert (name != NULL);
    zsys_debug1 ("number of all rules = '%zu'", ac.size ());
    for (const auto& i: ac) {
        const auto &rule = i.first;
        if (rule->hasSameNameAs (name))
        {
            zsys_debug1 ("found");
            zmsg_t *reply = zmsg_new ();
            zmsg_addstr (reply, "OK");
            zmsg_addstr (reply, rule->getJsonRule().c_str());

            mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            return;
        }
    }

    zsys_debug1 ("not found");
    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "ERROR");
    zmsg_addstr (reply, "NOT_FOUND");

    mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
    return;
}


static std::string
makeActionList(
    const std::vector <std::string> &actions)
{
    std::string s;
    bool first = true;
    for (const auto& oneAction : actions) {
        if (first) {
            s.append (oneAction);
            first = false;
        }
        else {
            s.append ("/").append (oneAction);
        }
    }
    return s;
}

static void
send_alerts(
    mlm_client_t *client,
    const std::vector <PureAlert> &alertsToSend,
    const std::string &rule_name)
{
    for ( const auto &alert : alertsToSend )
    {
        // create 3*ttl minutes alert TTL
        
        zmsg_t *msg = fty_proto_encode_alert (
            NULL,
            ::time (NULL),
            alert._ttl,
            rule_name.c_str(),
            alert._element.c_str(),
            alert._status.c_str(),
            alert._severity.c_str(),
            alert._description.c_str(),
            makeActionList(alert._actions).c_str()
        );
        if( msg ) {
            std::string atopic = rule_name + "/"
                + alert._severity + "@"
                + alert._element;
            mlm_client_send (client, atopic.c_str(), &msg);
            zsys_debug1 ("mlm_client_send (subject = '%s')", atopic.c_str());
        }
    }
}

static void
send_alerts(
    mlm_client_t *client,
    const std::vector <PureAlert> &alertsToSend,
    const RulePtr &rule)
{
    send_alerts (client, alertsToSend, rule->name());
}

static void
add_rule(
    mlm_client_t *client,
    const char *json_representation,
    AlertConfiguration &ac)
{
    std::istringstream f(json_representation);
    std::set <std::string> newSubjectsToSubscribe;
    std::vector <PureAlert> alertsToSend;
    AlertConfiguration::iterator new_rule_it;
    int rv = ac.addRule (f, newSubjectsToSubscribe, alertsToSend, new_rule_it);
    zmsg_t *reply = zmsg_new ();
    switch (rv) {
    case -2:
    {
        // rule exists
        zsys_debug1 ("rule already exists");
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "ALREADY_EXISTS");

        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        return;
    }
    case 0:
    {
        // rule was created succesfully
        /* TODO: WIP, don't delete
        zsys_debug1 ("newsubjects count = %d", newSubjectsToSubscribe.size() );
        zsys_debug1 ("alertsToSend count = %d", alertsToSend.size() );
        for ( const auto &interestedSubject : newSubjectsToSubscribe ) {
            zsys_debug1 ("Registering to receive '%s'", interestedSubject.c_str());
            mlm_client_set_consumer(client, METRICS_STREAM, interestedSubject.c_str());
            zsys_debug1("Registering finished");
        }
        */

        // send a reply back
        zsys_debug1 ("rule added correctly");
        zmsg_addstr (reply, "OK");
        zmsg_addstr (reply, json_representation)
            ;
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);

        // send updated alert
        send_alerts (client, alertsToSend, new_rule_it->first);
        return;
    }
    case -5:
    {
        zsys_debug1 ("rule has bad lua");
        // error during the rule creation (lua)
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_LUA");

        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        return;
    }
    case -6:
    {
        zsys_debug1 ("internal error");
        // error during the rule creation (lua)
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "Internal error - operating with storage/disk failed.");

        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        return;
    }
    default:
        // error during the rule creation
        zsys_debug1 ("default bad json");
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_JSON");

        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        return;
    }
}
static void
update_rule(
    mlm_client_t *client,
    const char *json_representation,
    const char *rule_name,
    AlertConfiguration &ac)
{
    std::istringstream f(json_representation);
    std::set <std::string> newSubjectsToSubscribe;
    std::vector <PureAlert> alertsToSend;
    AlertConfiguration::iterator new_rule_it;
    int rv = ac.updateRule (f, rule_name, newSubjectsToSubscribe, alertsToSend, new_rule_it);
    zmsg_t *reply = zmsg_new ();
    switch (rv) {
    case -2:
        zsys_debug1 ("rule not found");
        // ERROR rule doesn't exist
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "NOT_FOUND");
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        return;
    case 0:
        // rule was updated succesfully
        /* TODO: WIP, don't delete
        zsys_debug1 ("newsubjects count = %d", newSubjectsToSubscribe.size() );
        zsys_debug1 ("alertsToSend count = %d", alertsToSend.size() );
        for ( const auto &interestedSubject : newSubjectsToSubscribe ) {
            zsys_debug1 ("Registering to receive '%s'", interestedSubject.c_str());
            mlm_client_set_consumer(client, METRICS_STREAM, interestedSubject.c_str());
            zsys_debug1("Registering finished");
        }
        */
        // send a reply back
        zsys_debug1 ("rule updated");
        zmsg_addstr (reply, "OK");
        zmsg_addstr (reply, json_representation);
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        // send updated alert
        send_alerts (client, alertsToSend, new_rule_it->first);
        return;
    case -5:
        zsys_debug1 ("rule has incorrect lua");
        // error during the rule creation (lua)
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_LUA");
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        return;
    case -3:
        zsys_debug1 ("new rule name already exists");
        // rule with new rule name already exists
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "ALREADY_EXISTS");
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        return;
    case -6:
    {
        // error during the rule creation
        zsys_debug1 ("internal error");
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "Internal error - operating with storate/disk failed.");
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        return;
    }
    default:
        // error during the rule creation
        zsys_debug1 ("bad json default");
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_JSON");
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        return;
    }
}


static void
touch_rule(
    mlm_client_t *client,
    const char *rule_name,
    AlertConfiguration &ac,
    bool send_reply)
{
    std::vector <PureAlert> alertsToSend;

    int rv = ac.touchRule (rule_name, alertsToSend);
    switch (rv) {
        case -1: {
            zsys_debug1 ("touch_rule:%s: Rule was not found", rule_name);
            // ERROR rule doesn't exist
            if ( send_reply ) {
                zmsg_t *reply = zmsg_new ();
                if ( !reply ) {
                    zsys_error ("touch_rule:%s: Cannot create reply message.", rule_name);
                    return;
                }
                zmsg_addstr (reply, "ERROR");
                zmsg_addstr (reply, "NOT_FOUND");
                mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
            }
            return;
        }
        case 0: {
            // rule was touched
            // send a reply back
            zsys_debug1 ("touch_rule:%s: ok", rule_name);
            if ( send_reply ) {
                zmsg_t *reply = zmsg_new ();
                if ( !reply ) {
                    zsys_error ("touch_rule:%s: Cannot create reply message.", rule_name);
                    return;
                }
                zmsg_addstr (reply, "OK");
                mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
            }
            // send updated alert
            send_alerts (client, alertsToSend, rule_name); // TODO third parameter
            return;
        }
    }
}

void check_metrics (
    mlm_client_t *client,
    const char *metric_topic,
    AlertConfiguration &ac)
{
    for ( const auto &i: ac) {
        const auto &rule = i.first;
        if ( rule->isTopicInteresting (metric_topic) ) {
            touch_rule (client, rule->name().c_str(), ac, false);
        }
    }
}

static void
evaluate_metric(
    mlm_client_t *client,
    const MetricInfo &triggeringMetric,
    const MetricList &knownMetricValues,
    AlertConfiguration &ac)
{
    // Go through all known rules, and try to evaluate them
    for ( const auto &i : ac ) {
        const auto &rule = i.first;
        try {
            bool is_interresting = rule->isTopicInteresting (triggeringMetric.generateTopic());

            if ( !is_interresting) {
                continue;
            }
            zsys_debug1 (" ### Evaluate rule '%s'", rule->name().c_str());

            PureAlert pureAlert;
            int rv = rule->evaluate (knownMetricValues, pureAlert);
            if ( rv != 0 ) {
                zsys_error (" ### Cannot evaluate the rule '%s'", rule->name().c_str());
                continue;
            }

            PureAlert alertToSend;
            rv = ac.updateAlert (rule, pureAlert, alertToSend);
            alertToSend._ttl = triggeringMetric.getTtl () * 3;
            if ( rv == -1 ) {
                zsys_debug1 (" ### alert updated, nothing to send");
                // nothing to send
                continue;
            }
            send_alerts (client, {alertToSend}, rule);
        }
        catch ( const std::exception &e) {
            zsys_error ("CANNOT evaluate rule, because '%s'", e.what());
        }
    }
}

void
fty_alert_engine_server (zsock_t *pipe, void* args)
{
    MetricList cache; // need to track incoming measurements
    AlertConfiguration alertConfiguration;
    char *name = (char*) args;

    mlm_client_t *client = mlm_client_new ();
    assert (client);

    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (client), NULL);
    assert (poller);

    uint64_t timeout = 30000;

    zsock_signal (pipe, 0);

    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, timeout);
        if (which == NULL) {
            if (zpoller_terminated (poller) || zsys_interrupted) {
                zsys_warning ("%s: zpoller_terminated () or zsys_interrupted. Shutting down.", name);
                break;
            }
            if (zpoller_expired (poller)) {
            }
            continue;
        }

        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            char *cmd = zmsg_popstr (msg);

            if (streq (cmd, "$TERM")) {
                zsys_debug1 ("%s: $TERM received", name);
                zstr_free (&cmd);
                zmsg_destroy (&msg);
                goto exit;
            }
            else
            if (streq (cmd, "VERBOSE")) {
                zsys_debug1 ("%s: VERBOSE received", name);
                agent_alert_verbose = true;
            }
            else
            if (streq (cmd, "CONNECT")) {
                zsys_debug1 ("CONNECT received");
                char* endpoint = zmsg_popstr (msg);
                int rv = mlm_client_connect (client, endpoint, 1000, name);
                if (rv == -1)
                    zsys_error ("%s: can't connect to malamute endpoint '%s'", name, endpoint);
                zstr_free (&endpoint);
            }
            else
            if (streq (cmd, "PRODUCER")) {
                zsys_debug1 ("PRODUCER received");
                char* stream = zmsg_popstr (msg);
                int rv = mlm_client_set_producer (client, stream);
                if (rv == -1)
                    zsys_error ("%s: can't set producer on stream '%s'", name, stream);
                zstr_free (&stream);
            }
            else
            if (streq (cmd, "CONSUMER")) {
                zsys_debug1 ("CONSUMER received");
                char* stream = zmsg_popstr (msg);
                char* pattern = zmsg_popstr (msg);
                int rv = mlm_client_set_consumer (client, stream, pattern);
                if (rv == -1)
                    zsys_error ("%s: can't set consumer on stream '%s', '%s'", name, stream, pattern);
                zstr_free (&pattern);
                zstr_free (&stream);
            }
            else
            if (streq (cmd, "CONFIG")) {
                zsys_debug1 ("CONFIG received");
                char* filename = zmsg_popstr (msg);
                if ( filename ) {
                    // Read initial configuration
                    alertConfiguration.setPath(filename);
                    // XXX: somes to subscribe are returned, but not used for now
                    alertConfiguration.readConfiguration();
                }
                else {
                    zsys_error ("%s: in CONFIG command next frame is missing", name);
                }
                zstr_free (&filename);
            }
            zstr_free (&cmd);
            zmsg_destroy (&msg);
            continue;
        }

        // This agent is a reactive agent, it reacts only on messages
        // and doesn't do anything if there is no messages
        // TODO: probably alert also should be send every XXX seconds,
        // even if no measurements were recieved
        zmsg_t *zmessage = mlm_client_recv (client);
        if ( zmessage == NULL ) {
            continue;
        }
        std::string topic = mlm_client_subject(client);
        // There are two possible inputs and they come in different ways
        // from the stream  -> metrics
        // from the mailbox -> rules
        //                  -> request for rule list
        // but even so we try to decide according what we got, not from where
        if ( is_fty_proto(zmessage) ) {
            fty_proto_t *bmessage = fty_proto_decode(&zmessage);
            if( ! bmessage ) {
                zsys_error ("%s: can't decode message with topic %s, ignoring", name, topic.c_str());
                continue;
            }
            if ( fty_proto_id(bmessage) == FTY_PROTO_METRIC )  {
                // process as metric message
                const char *type = fty_proto_type(bmessage);
                const char * name = fty_proto_name (bmessage);
                const char *value = fty_proto_value(bmessage);
                const char *unit = fty_proto_unit(bmessage);
                uint32_t ttl = fty_proto_ttl(bmessage);
                uint64_t timestamp = fty_proto_aux_number (bmessage, "time", ::time(NULL));
                // TODO: 2016-04-27 ACE: fix it later, when "string" values
                // in the metric would be considered as
                // normal behaviour, but for now it is not supposed to be so
                // -> generated error messages into the log
                char *end;
                double dvalue = strtod (value, &end);
                if (errno == ERANGE) {
                    errno = 0;
                    fty_proto_print (bmessage);
                    zsys_error ("%s: can't convert value to double #1, ignore message", name);
                    fty_proto_destroy (&bmessage);
                    continue;
                }
                else if (end == value || *end != '\0') {
                    fty_proto_print (bmessage);
                    zsys_error ("%s: can't convert value to double #2, ignore message", name);
                    fty_proto_destroy (&bmessage);
                    continue;
                }

                zsys_debug1("%s: Got message '%s' with value %s", name, topic.c_str(), value);

                // Update cache with new value
                MetricInfo m (name, type, unit, dvalue, timestamp, "", ttl);
                fty_proto_destroy(&bmessage);
                cache.addMetric (m);
                cache.removeOldMetrics();
                evaluate_metric(client, m, cache, alertConfiguration);
            }
            fty_proto_destroy (&bmessage);
        }
        // According RFC we expect here a messages
        // with the topic:
        //   * RULE_SUBJECT
        else
        if ( streq (mlm_client_subject (client), RULES_SUBJECT) ) {
            zsys_debug1 ("%s", RULES_SUBJECT);
            // Here we can have:
            //  * request for list of rules
            //  * get detailed info about the rule
            //  * new/update rule
            //  * touch rule
            char *command = zmsg_popstr (zmessage);
            char *param = zmsg_popstr (zmessage);
            if (command && param) {
                if (streq (command, "LIST")) {
                    char *rule_class = zmsg_popstr (zmessage);
                    list_rules (client, param, rule_class, alertConfiguration);
                    zstr_free (&rule_class);
                }
                else if (streq (command, "GET")) {
                    get_rule (client, param, alertConfiguration);
                }
                else if (streq (command, "ADD") ) {
                    if ( zmsg_size(zmessage) == 0 ) {
                        // ADD/json
                        add_rule (client, param, alertConfiguration);
                    }
                    else {
                        // ADD/json/old_name
                        char *param1 = zmsg_popstr (zmessage);
                        update_rule (client, param, param1, alertConfiguration);
                        if (param1) free (param1);
                    }
                } else if (streq (command, "TOUCH") ) {
                    touch_rule (client, param, alertConfiguration, true);
                }
                else {
                    zsys_error ("Received unexpected message to MAIBOX with command '%s'", command);
                }
            }
            zstr_free (&command);
            zstr_free (&param);
        }
        else {
            // Here we can have a message with arbitrary topic, but according protocol
            // first frame must be one of the following:
            //  * METIC_UNAVAILABLE
            char *command = zmsg_popstr (zmessage);
            if (streq (command, "METRICUNAVAILABLE")) {
                char *metrictopic = zmsg_popstr (zmessage);
                if (metrictopic) {
                    check_metrics (client, metrictopic, alertConfiguration);
                }
                else {
                    zsys_error ("%s: Received command '%s', but message has bad format", name, command);
                }
                zstr_free (&metrictopic);
            }
            else {
                zsys_error ("%s: Unexcepted message received", name);
            }
            zstr_free (&command);
        }
        zmsg_destroy (&zmessage);
    }
exit:
    zpoller_destroy (&poller);
    mlm_client_destroy (&client);
}

//  --------------------------------------------------------------------------
//  Self test of this class.

static char*
s_readall (const char* filename) {
    FILE *fp = fopen(filename, "rt");
    if (!fp)
        return NULL;

    size_t fsize = 0;
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *ret = (char*) malloc (fsize * sizeof (char) + 1);
    if (!ret) {
        fclose (fp);
        return NULL;
    }
    memset ((void*) ret, '\0', fsize * sizeof (char) + 1);

    size_t r = fread((void*) ret, 1, fsize, fp);
    fclose (fp);
    if (r == fsize)
        return ret;

    free (ret);
    return NULL;
}


void
fty_alert_engine_server_test (bool verbose)
{
    printf (" * fty_alert_engine_server: ");
    if (verbose)
        printf ("\n");

    int r = system ("rm -f src/*.rule");
    assert (r == 0); // to make gcc @ CentOS 7 happy

    //  @selftest
    static const char* endpoint = "inproc://fty-ag-server-test";

    zactor_t *server = zactor_new (mlm_server, (void*) "Malamute");
    zstr_sendx (server, "BIND", endpoint, NULL);
    if (verbose)
        zstr_send (server, "VERBOSE");

    mlm_client_t *producer = mlm_client_new ();
    mlm_client_connect (producer, endpoint, 1000, "producer");
    mlm_client_set_producer (producer, FTY_PROTO_STREAM_METRICS);

    mlm_client_t *consumer = mlm_client_new ();
    mlm_client_connect (consumer, endpoint, 1000, "consumer");
    mlm_client_set_consumer (consumer, FTY_PROTO_STREAM_ALERTS_SYS, ".*");

    mlm_client_t *ui = mlm_client_new ();
    mlm_client_connect (ui, endpoint, 1000, "UI");

    zactor_t *ag_server = zactor_new (fty_alert_engine_server, (void*) "alert-agent");
    if (verbose)
        zstr_send (ag_server, "VERBOSE");
    zstr_sendx (ag_server, "CONNECT", endpoint, NULL);
    zstr_sendx (ag_server, "CONSUMER", FTY_PROTO_STREAM_METRICS, ".*", NULL);
    zstr_sendx (ag_server, "CONSUMER", FTY_PROTO_STREAM_METRICS_UNAVAILABLE, ".*", NULL);
    zstr_sendx (ag_server, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);
    zstr_sendx (ag_server, "CONFIG", "src/", NULL);
    zclock_sleep (500);   //THIS IS A HACK TO SETTLE DOWN THINGS

    // Test case #1: list w/o rules
    {
    zmsg_t *command = zmsg_new ();
    zmsg_addstrf (command, "%s", "LIST");
    zmsg_addstrf (command, "%s", "all");
    zmsg_addstrf (command, "%s", "");
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &command);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 3);
    char * foo = zmsg_popstr (recv);
    assert (streq (foo, "LIST"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "all"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, ""));
    zstr_free (&foo);
    zmsg_destroy (&recv);
    }
    // Test case #2.0: add new rule
    {
    zmsg_t *rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char* simplethreshold_rule = s_readall ("testrules/simplethreshold3.rule");
    assert (simplethreshold_rule);
    zmsg_addstrf (rule, "%s", simplethreshold_rule);
    zstr_free (&simplethreshold_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);
    }
    // Test case #2.1: add new rule
    {
    zmsg_t *rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char* simplethreshold_rule = s_readall ("testrules/simplethreshold.rule");
    assert (simplethreshold_rule);
    zmsg_addstrf (rule, "%s", simplethreshold_rule);
    zstr_free (&simplethreshold_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);
    // Test case #2.3: existing rule: simplethreshold
    //                 existing rule: simplethreshold2
    //                 update simplethreshold2 with new name simplethreshold
    rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    simplethreshold_rule = s_readall ("testrules/simplethreshold2.rule");
    assert (simplethreshold_rule);
    zmsg_addstrf (rule, "%s", simplethreshold_rule);
    zstr_free (&simplethreshold_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);

    rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    simplethreshold_rule = s_readall ("testrules/simplethreshold.rule");
    assert (simplethreshold_rule);
    zmsg_addstrf (rule, "%s", simplethreshold_rule);
    zstr_free (&simplethreshold_rule);
    zmsg_addstrf (rule, "%s", "simplethreshold2");
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "ERROR"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "ALREADY_EXISTS"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);
    //Test case #5: generate alert - below the treshold
    zmsg_t *m = fty_proto_encode_metric (
            NULL, time (NULL), 0, "abc", "fff", "20", "X");
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);

    assert (is_fty_proto (recv));
    fty_proto_t *brecv = fty_proto_decode (&recv);
    assert (streq (fty_proto_rule (brecv), "simplethreshold"));
    assert (streq (fty_proto_name (brecv), "fff"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    fty_proto_destroy (&brecv);

    // Test case #6: generate alert - resolved
    m = fty_proto_encode_metric (
            NULL, time (NULL), 0, "abc", "fff", "42", "X");
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);

    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (streq (fty_proto_rule (brecv), "simplethreshold"));
    assert (streq (fty_proto_name (brecv), "fff"));
    assert (streq (fty_proto_state (brecv), "RESOLVED"));
    fty_proto_destroy (&brecv);
    // Test case #6: generate alert - high warning
    m = fty_proto_encode_metric (
            NULL, time (NULL), 0, "abc", "fff", "52", "X");
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);

    assert (recv);
    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (brecv);
    assert (streq (fty_proto_rule (brecv), "simplethreshold"));
    assert (streq (fty_proto_name (brecv), "fff"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "WARNING"));
    fty_proto_destroy (&brecv);
    // Test case #7: generate alert - high critical
    m = fty_proto_encode_metric (
            NULL, time (NULL), 0, "abc", "fff", "62", "X");
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);

    assert (recv);
    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (brecv);
    assert (streq (fty_proto_rule (brecv), "simplethreshold"));
    assert (streq (fty_proto_name (brecv), "fff"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    fty_proto_destroy (&brecv);
    // Test case #8: generate alert - resolved again
    m = fty_proto_encode_metric (
            NULL, time (NULL), 0, "abc", "fff", "42", "X");
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);

    assert (recv);
    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (brecv);
    assert (streq (fty_proto_rule (brecv), "simplethreshold"));
    assert (streq (fty_proto_name (brecv), "fff"));
    assert (streq (fty_proto_state (brecv), "RESOLVED"));
    fty_proto_destroy (&brecv);
    // Test case #9: generate alert - high again
    m = fty_proto_encode_metric (
            NULL, time (NULL), 0, "abc", "fff", "62", "X");
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);

    assert (recv);
    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (brecv);
    assert (streq (fty_proto_rule (brecv), "simplethreshold"));
    assert (streq (fty_proto_name (brecv), "fff"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    fty_proto_destroy (&brecv);
    // Test case #11: generate alert - high again
    m = fty_proto_encode_metric (
            NULL, time (NULL), 0, "abc", "fff", "62", "X");
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);
    assert (recv);
    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (brecv);
    assert (streq (fty_proto_rule (brecv), "simplethreshold"));
    assert (streq (fty_proto_name (brecv), "fff"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    fty_proto_destroy (&brecv);
    // Test case #12: generate alert - resolved
    m = fty_proto_encode_metric (
            NULL, time (NULL), 0, "abc", "fff", "42", "X");
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);
    assert (recv);
    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (brecv);
    assert (streq (fty_proto_rule (brecv), "simplethreshold"));
    assert (streq (fty_proto_name (brecv), "fff"));
    assert (streq (fty_proto_state (brecv), "RESOLVED"));
    fty_proto_destroy (&brecv);
    }
    // Test case #2.2: add new rule with existing name
    {
    zmsg_t *rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char *simplethreshold_rule = s_readall ("testrules/simplethreshold.rule");
    assert (simplethreshold_rule);
    zmsg_addstrf (rule, "%s", simplethreshold_rule);
    zstr_free (&simplethreshold_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "ERROR"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "ALREADY_EXISTS"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);
    }
    // Test case #3: list rules
    {
    zmsg_t *command = zmsg_new ();
    zmsg_addstrf (command, "%s", "LIST");
    zmsg_addstrf (command, "%s", "all");
    zmsg_addstrf (command, "%s", "");
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &command);

    zmsg_t *recv = mlm_client_recv (ui);
    
    assert (zmsg_size (recv) == 6);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "LIST"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "all"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, ""));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);
    }
    // Test case #4: list rules - not yet stored type
    {
    zmsg_t *command = zmsg_new ();
    zmsg_addstrf (command, "%s", "LIST");
    zmsg_addstrf (command, "%s", "single");
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &command);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 3);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "LIST"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "single"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, ""));
    zstr_free (&foo);
    zmsg_destroy (&recv);
    }
    // Test case #4.1: list w/o rules
    {
    zmsg_t *command = zmsg_new ();
    zmsg_addstrf (command, "%s", "LIST");
    zmsg_addstrf (command, "%s", "all");
    zmsg_addstrf (command, "%s", "example class");
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &command);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 4);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "LIST"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "all"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "example class"));
    zstr_free (&foo);
    zmsg_destroy (&recv);
    }
    // Test case #13: segfault on onbattery
    // #13.1 ADD new rule
    {
    zmsg_t *rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char* onbattery_rule = s_readall ("testrules/onbattery-5PX1500-01.rule");
    assert (onbattery_rule);
    zmsg_addstrf (rule, "%s", onbattery_rule);
    zstr_free (&onbattery_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    zmsg_t *recv = mlm_client_recv (ui);
    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);
    // #13.2 evaluate metric
    zmsg_t *m = fty_proto_encode_metric (
           NULL, ::time (NULL), ::time (NULL), "status.ups", "5PX1500-01", "1032.000", "");
    mlm_client_send (producer, "status.ups@5PX1500-01", &m);
    }
    // Test case #14: add new rule, but with lua syntax error
    {
    zmsg_t *rule = zmsg_new();
    assert(rule);
    zmsg_addstrf (rule, "%s", "ADD");
    char* complexthreshold_rule_lua_error = s_readall ("testrules/complexthreshold_lua_error.rule");
    assert (complexthreshold_rule_lua_error);
    zmsg_addstrf (rule, "%s", complexthreshold_rule_lua_error);
    zstr_free (&complexthreshold_rule_lua_error);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    zmsg_t *recv = mlm_client_recv (ui);
    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "ERROR"));
    zstr_free (&foo);
    foo = zmsg_popstr(recv);
    assert (streq (foo, "BAD_LUA"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);
    }
    // Test case #15.1: add Radek's testing rule
    {
    zmsg_t *rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char* toohigh_rule = s_readall ("testrules/too_high-ROZ.ePDU13.rule");
    assert (toohigh_rule);
    zmsg_addstrf (rule, "%s", toohigh_rule);
    zstr_free (&toohigh_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    zmsg_destroy (&recv);

    // Test case #15.2: evaluate it
    zmsg_t *m = fty_proto_encode_metric (
            NULL, ::time (NULL), ::time (NULL), "status.ups", "ROZ.UPS33", "42.00", "");
    mlm_client_send (producer, "status.ups@ROZ.UPS33", &m);

    recv = mlm_client_recv (consumer);

    assert (recv);
    assert (is_fty_proto (recv));
    fty_proto_t *brecv = fty_proto_decode (&recv);
    assert (brecv);
    assert (streq (fty_proto_rule (brecv), "too_high-ROZ.ePDU13"));
    assert (streq (fty_proto_name (brecv), "ePDU13"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    fty_proto_destroy (&brecv);

    // Test case #15.3: evaluate it again
    m = fty_proto_encode_metric (
            NULL, ::time (NULL), ::time (NULL), "status.ups", "ROZ.UPS33", "42.00", "");
    mlm_client_send (producer, "status.ups@ROZ.UPS33", &m);

    recv = mlm_client_recv (consumer);

    assert (recv);
    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (brecv);
    assert (streq (fty_proto_rule (brecv), "too_high-ROZ.ePDU13"));
    assert (streq (fty_proto_name (brecv), "ePDU13"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    fty_proto_destroy (&brecv);
    zmsg_destroy (&recv);
    }
    // Test case #16.1: add new rule, with the trash at the end
    {
    zmsg_t *rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char* rule_with_trash = s_readall ("testrules/rule_with_trash.rule");
    assert (rule_with_trash);
    zmsg_addstrf (rule, "%s", rule_with_trash);
    zstr_free (&rule_with_trash);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);

    // Test case #16.2: add new rule, GET the rule with trash
    zmsg_t *command = zmsg_new ();
    zmsg_addstrf (command, "%s", "GET");
    zmsg_addstrf (command, "%s", "rule_with_trash");
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &command);

    recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    std::stringstream s{foo};
    cxxtools::JsonDeserializer d{s};
    cxxtools::SerializationInfo si;
    d.deserialize (si);
    assert (si.memberCount () == 1);
    zstr_free (&foo);
    zmsg_destroy (&recv);
    }
    // test case #17 update the existing rule (type: threshold_simple)
    // input:
    //          * file check_update_threshold_simple.rule
    //          * file check_update_threshold_simple2.rule
    //      rules inside the files have the same names, but
    //      "values" are different
    // 1. add rule from the file check_update_threshold_simple.rule
    // 2. update "check_update_threshold_simple" rule with file "check_update_threshold_simple2.rule"
    //
    // expected result: SUCCESS
    // 1.
    {
    zmsg_t *rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char *simplethreshold_rule = s_readall ("testrules/check_update_threshold_simple.rule");
    assert (simplethreshold_rule);
    zmsg_addstrf (rule, "%s", simplethreshold_rule);
    zstr_free (&simplethreshold_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);

    // 2.
    rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    simplethreshold_rule = s_readall ("testrules/check_update_threshold_simple2.rule");
    assert (simplethreshold_rule);
    zmsg_addstrf (rule, "%s", simplethreshold_rule);
    zstr_free (&simplethreshold_rule);
    zmsg_addstrf (rule, "%s", "check_update_threshold_simple");
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    // check the result of the operation
    recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);
    }
    // ######## Test case #18 
    // 18.1 add some rule (type: pattern)
    {
    zsys_info ("######## Test case #18 add some rule (type: pattern)");
    zmsg_t *rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char* pattern_rule = s_readall ("testrules/pattern.rule");
    assert (pattern_rule);
    zmsg_addstrf (rule, "%s", pattern_rule);
    zstr_free (&pattern_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);
    // 18.2 evaluate some rule (type: pattern)
    zsys_info ("######## Test case #19 evaluate some rule (type: pattern)");
    //  18.2.1. OK
    zmsg_t *m = fty_proto_encode_metric (
            NULL, ::time (NULL), 24*60*60, "end_warranty_date", "UPS_pattern_rule", "100", "some description");
    mlm_client_send (producer, "end_warranty_date@UPS_pattern_rule", &m);

    // 18.2.1.1. No ALERT should be generated
    zpoller_t *poller = zpoller_new (mlm_client_msgpipe(consumer), NULL);
    void *which = zpoller_wait (poller, 1000);
    assert ( which == NULL );
    if ( verbose ) {
        zsys_debug ("No alert was sent: SUCCESS");
    }
    zpoller_destroy (&poller);

    // 18.2.2 LOW_WARNING
    m = fty_proto_encode_metric (
            NULL, ::time (NULL), 24*60*60, "end_warranty_date", "UPS_pattern_rule", "20", "some description");
    mlm_client_send (producer, "end_warranty_date@UPS_pattern_rule", &m);

    recv = mlm_client_recv (consumer);
    assert ( recv != NULL );
    assert (is_fty_proto (recv));
    fty_proto_t *brecv = fty_proto_decode (&recv);
    assert (streq (fty_proto_rule (brecv), "warranty2"));
    assert (streq (fty_proto_name (brecv), "UPS_pattern_rule"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "WARNING"));
    fty_proto_destroy (&brecv);

    // 18.2.3 LOW_CRITICAL
    m = fty_proto_encode_metric (
            NULL, ::time (NULL), 24*60*60, "end_warranty_date", "UPS_pattern_rule", "2", "some description");
    mlm_client_send (producer, "end_warranty_date@UPS_pattern_rule", &m);

    recv = mlm_client_recv (consumer);
    assert ( recv != NULL );
    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (streq (fty_proto_rule (brecv), "warranty2"));
    assert (streq (fty_proto_name (brecv), "UPS_pattern_rule"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    fty_proto_destroy (&brecv);

    zstr_free (&foo);
    zstr_free (&pattern_rule);
    zmsg_destroy (&recv);
    }
    // Test case #21:   Thresholds imported from devices
    {
    //      21.1.1  add existing rule: devicethreshold
    zmsg_t *rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char *devicethreshold_rule = s_readall ("testrules/devicethreshold.rule");
    assert (devicethreshold_rule);
    zmsg_addstrf (rule, "%s", devicethreshold_rule);
    zstr_free (&devicethreshold_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);

    //      21.1.2  add existing rule second time: devicethreshold
    rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    devicethreshold_rule = s_readall ("testrules/devicethreshold2.rule");
    assert (devicethreshold_rule);
    zmsg_addstrf (rule, "%s", devicethreshold_rule);
    zstr_free (&devicethreshold_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "ERROR"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "ALREADY_EXISTS"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);

    //      21.2  update existing rule
    rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    devicethreshold_rule = s_readall ("testrules/devicethreshold2.rule");
    assert (devicethreshold_rule);
    zmsg_addstrf (rule, "%s", devicethreshold_rule);
    zstr_free (&devicethreshold_rule);
    zmsg_addstrf (rule, "%s", "device_threshold_test"); // name of the rule
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);

    //      21.3  check that alert is not generated

    zmsg_t *m = fty_proto_encode_metric (
            NULL, ::time (NULL), 600, "device_metric", "ggg", "100", "");
    mlm_client_send (producer, "device_metric@ggg", &m);

    zpoller_t *poller = zpoller_new (mlm_client_msgpipe(consumer), NULL);
    void *which = zpoller_wait (poller, 1000);
    assert ( which == NULL );
    if ( verbose ) {
        zsys_debug ("No alert was sent: SUCCESS");
    }
    zpoller_destroy (&poller);
    }
    // Test 22: a simple threshold with not double value
    // actually, this "behaviour" would automatically apply to ALL rules,
    // as it is implemented in rule.class
    // 22-1 : "AA20"
    {
    zmsg_t *rule = zmsg_new();
    zmsg_addstr (rule, "ADD");
    char *simplethreshold_rule = s_readall ("testrules/simplethreshold_string_value1.rule");
    assert (simplethreshold_rule);
    zmsg_addstr (rule, simplethreshold_rule);
    zstr_free (&simplethreshold_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "ERROR"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    zsys_info (foo);
    assert (streq (foo, "BAD_JSON"));
    zstr_free (&foo);
    zmsg_destroy (&recv);

    // 22-2 : "20AA"
    rule = zmsg_new();
    zmsg_addstr (rule, "ADD");
    simplethreshold_rule = s_readall ("testrules/simplethreshold_string_value2.rule");
    assert (simplethreshold_rule);
    zmsg_addstr (rule, simplethreshold_rule);
    zstr_free (&simplethreshold_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "ERROR"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    zsys_info (foo);
    assert (streq (foo, "BAD_JSON"));
    zstr_free (&foo);
    zmsg_destroy (&recv);
    }
    // test 23: touch rule, that doesn't exist
    {
    zmsg_t *touch_request = zmsg_new ();
    assert (touch_request);
    zmsg_addstr (touch_request, "TOUCH");
    zmsg_addstr (touch_request, "rule_to_touch_doesnt_exists");
    int rv = mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &touch_request);
    assert ( rv == 0 );

    zmsg_t *recv = mlm_client_recv (ui);
    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "ERROR"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "NOT_FOUND"));
    zstr_free (&foo);
    zmsg_destroy (&recv);
    }
    // test 24: touch rule that exists
    {
    // 24.1 Create a rule we are going to test against
    zmsg_t *rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char *rule_to_touch = s_readall ("testrules/rule_to_touch.rule");
    assert (rule_to_touch);
    zmsg_addstrf (rule, "%s", rule_to_touch);
    zstr_free (&rule_to_touch);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);

    // 24.1.1 there is no any alerts on the rule; send touch request
    zmsg_t *touch_request = zmsg_new ();
    assert (touch_request);
    zmsg_addstr (touch_request, "TOUCH");
    zmsg_addstr (touch_request, "rule_to_touch");
    int rv = mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &touch_request);
    assert ( rv == 0 );

    recv = mlm_client_recv (ui);
    assert (recv);
    assert (zmsg_size (recv) == 1);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    zmsg_destroy (&recv);

    // 24.1.2 No ALERT should be generated/regenerated/closed
    zpoller_t *poller = zpoller_new (mlm_client_msgpipe (consumer), NULL);
    assert (poller);
    void *which = zpoller_wait (poller, 1000);
    assert ( which == NULL );
    if ( verbose ) {
        zsys_debug ("No alert was sent: SUCCESS");
    }
    zpoller_destroy (&poller);

    // 24.2.1.1 there exists ACTIVE alert (as there were no alerts, lets create one :)); send metric
    zmsg_t *m = fty_proto_encode_metric (
            NULL, ::time (NULL), 0, "metrictouch", "assettouch", "10", "X");
    assert (m);
    rv = mlm_client_send (producer, "metrictouch@assettouch", &m);
    assert ( rv == 0 );

    // 24.2.1.2 receive alert
    recv = mlm_client_recv (consumer);
    assert (recv);
    assert (is_fty_proto (recv));
    fty_proto_t *brecv = fty_proto_decode (&recv);
    assert (brecv);
    assert (streq (fty_proto_rule (brecv), "rule_to_touch"));
    assert (streq (fty_proto_name (brecv), "assettouch"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    fty_proto_destroy (&brecv);

    // 24.2.2 send touch request
    touch_request = zmsg_new ();
    assert (touch_request);
    zmsg_addstr (touch_request, "TOUCH");
    zmsg_addstr (touch_request, "rule_to_touch");
    rv = mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &touch_request);
    assert ( rv == 0 );

    recv = mlm_client_recv (ui);
    assert (recv);
    assert (zmsg_size (recv) == 1);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    zmsg_destroy (&recv);

    // 24.2.3 the only existing ALERT must be RESOLVED
    poller = zpoller_new (mlm_client_msgpipe (consumer), NULL);
    assert (poller);
    which = zpoller_wait (poller, 1000);
    assert ( which != NULL );
    recv = mlm_client_recv (consumer);
    assert ( recv != NULL );
    assert ( is_fty_proto (recv));
    if ( verbose ) {
        brecv = fty_proto_decode (&recv);
        assert (streq (fty_proto_rule (brecv), "rule_to_touch"));
        assert (streq (fty_proto_name (brecv), "assettouch"));
        assert (streq (fty_proto_state (brecv), "RESOVLED"));
        assert (streq (fty_proto_severity (brecv), "CRITICAL"));
        fty_proto_destroy (&brecv);
        zsys_debug ("Alert was sent: SUCCESS");
    }
    zmsg_destroy (&recv);
    zpoller_destroy (&poller);

    // 24.3.1: there exists a RESOLVED alert for this rule; send touch request
    touch_request = zmsg_new ();
    assert (touch_request);
    zmsg_addstr (touch_request, "TOUCH");
    zmsg_addstr (touch_request, "rule_to_touch");
    rv = mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &touch_request);
    assert ( rv == 0 );

    recv = mlm_client_recv (ui);
    assert (recv);
    assert (zmsg_size (recv) == 1);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    zmsg_destroy (&recv);

    // 24.3.2 NO alert should be generated
    poller = zpoller_new (mlm_client_msgpipe (consumer), NULL);
    assert (poller);
    which = zpoller_wait (poller, 1000);
    assert ( which == NULL );
    if ( verbose ) {
        zsys_debug ("No alert was sent: SUCCESS");
    }
    zpoller_destroy (&poller);
    }
    // test 25: metric_unavailable
    // 25.1 Create a rules we are going to test against; add First rule
    {
    zmsg_t *rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char *rule_to_touch = s_readall ("testrules/rule_to_metrictouch1.rule");
    assert (rule_to_touch);
    zmsg_addstrf (rule, "%s", rule_to_touch);
    zstr_free (&rule_to_touch);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);

    // 25.2 Add Second rule
    rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    rule_to_touch = s_readall ("testrules/rule_to_metrictouch2.rule");
    assert (rule_to_touch);
    zmsg_addstrf (rule, "%s", rule_to_touch);
    zstr_free (&rule_to_touch);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);

    // 25.3.1 Generate alert on the First rule; send metric
    zmsg_t *m = fty_proto_encode_metric (
            NULL, ::time (NULL), 0, "metrictouch1", "element1", "100", "X");
    assert (m);
    int rv = mlm_client_send (producer, "metrictouch1@element1", &m);
    assert ( rv == 0 );

    // 25.3.2 receive alert
    recv = mlm_client_recv (consumer);
    assert (recv);
    assert (is_fty_proto (recv));
    fty_proto_t *brecv = fty_proto_decode (&recv);
    assert (brecv);
    assert (streq (fty_proto_rule (brecv), "rule_to_metrictouch1"));
    assert (streq (fty_proto_name (brecv), "element3"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    fty_proto_destroy (&brecv);

    // 25.4.1 Generate alert on the Second rule; send metric
    m = fty_proto_encode_metric (
            NULL, ::time (NULL), 0, "metrictouch2", "element2", "80", "X");
    assert (m);
    rv = mlm_client_send (producer, "metrictouch2@element2", &m);
    assert ( rv == 0 );

    // 25.4.2 receive alert
    recv = mlm_client_recv (consumer);
    assert (recv);
    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (brecv);
    assert (streq (fty_proto_rule (brecv), "rule_to_metrictouch2"));
    assert (streq (fty_proto_name (brecv), "element3"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "WARNING"));
    fty_proto_destroy (&brecv);

    // 25.5 Send "metric unavailable"
    // 25.5.1. We need a special client for this
    mlm_client_t *metric_unavailable = mlm_client_new ();
    mlm_client_connect (metric_unavailable, endpoint, 1000, "metricunavailable");
    mlm_client_set_producer (metric_unavailable, "_METRICS_UNAVAILABLE");

    // 25.5.2. send UNAVAILABLE metric
    zmsg_t *m_unavailable = zmsg_new();
    assert (m_unavailable);
    zmsg_addstr (m_unavailable, "METRICUNAVAILABLE");
    zmsg_addstr (m_unavailable, "metrictouch1@element1");

    rv = mlm_client_send (metric_unavailable, "metrictouch1@element1", &m_unavailable);
    assert ( rv == 0 );

    // 25.6 Check that 2 alerts were resolved
    recv = mlm_client_recv (consumer);
    assert (recv);
    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (brecv);
    assert (streq (fty_proto_state (brecv), "RESOLVED"));
    fty_proto_destroy (&brecv);

    recv = mlm_client_recv (consumer);
    assert (recv);
    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (brecv);
    assert (streq (fty_proto_name (brecv), "element3"));
    assert (streq (fty_proto_state (brecv), "RESOLVED"));
    fty_proto_destroy (&brecv);

    // 25.7 clean up
    mlm_client_destroy (&metric_unavailable);
    }
    // # 26 - # 29 : test autoconfig
    mlm_client_t *asset_producer = mlm_client_new ();
    mlm_client_connect (asset_producer, endpoint, 1000, "asset_producer");
    mlm_client_set_producer (asset_producer, FTY_PROTO_STREAM_ASSETS);

    zactor_t *ag_configurator = zactor_new (autoconfig, (void*) "test-autoconfig");
    if (verbose)
            zstr_send (ag_configurator, "VERBOSE");
    zstr_sendx (ag_configurator, "CONNECT", endpoint, NULL);
    zstr_sendx (ag_configurator, "TEMPLATES_DIR", "src/templates", NULL);
    zstr_sendx (ag_configurator, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    zstr_sendx (ag_configurator, "ALERT_ENGINE_NAME", "alert-agent", NULL);
    zclock_sleep (500);   //THIS IS A HACK TO SETTLE DOWN THINGS

    // # 26.1 catch message 'create asset', check that we created rules
    { 
    zhash_t *aux = zhash_new ();
    zhash_autofree (aux);
    zhash_insert (aux, "type", (void *) "datacenter");
    zhash_insert (aux, "priority", (void *) "P1");
    zmsg_t *m = fty_proto_encode_asset (aux,
            "test",
            FTY_PROTO_ASSET_OP_CREATE,
            NULL);
    assert (m);
    zhash_destroy (&aux);
    int rv = mlm_client_send (asset_producer, "datacenter.@test", &m);
    assert ( rv == 0 );

    zclock_sleep (6000);

    char *average_humidity = s_readall ((std::string ("src") + "/average.humidity@test.rule").c_str ());
    assert (average_humidity);
    char *average_temperature = s_readall ((std::string ("src") + "/average.temperature@test.rule").c_str ());
    assert (average_temperature);
    char *realpower_default =  s_readall ((std::string ("src") + "/realpower.default@test.rule").c_str ());
    assert (realpower_default);
    char *phase_imbalance = s_readall ((std::string ("src") + "/phase_imbalance@test.rule").c_str ());
    assert (phase_imbalance);

    zstr_free (&realpower_default);
    zstr_free (&phase_imbalance);
    zstr_free (&average_humidity);
    zstr_free (&average_temperature);
    // # 26.2 force an alert
    int ttl = 60;
    m = fty_proto_encode_metric (
        NULL, ::time (NULL), ttl, "average.temperature", "test", "1000", "C");
    assert (m);
    rv = mlm_client_send (producer, "average.temperature@test", &m);
    assert ( rv == 0 );

    zmsg_t *recv = mlm_client_recv (consumer);
    assert (recv);
    assert (is_fty_proto (recv));
    fty_proto_t *brecv = fty_proto_decode (&recv);
    assert (brecv);
    ttl = fty_proto_ttl (brecv);
    assert (ttl != -1);
    assert (streq (fty_proto_rule (brecv), "average.temperature@test"));
    assert (streq (fty_proto_name (brecv), "test"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    fty_proto_destroy (&brecv);
    }
    // # 27.1 update the created asset, check that we have the rules, wait for 3*ttl,
    // refresh the metric, check that we still have the alert
    {
    zhash_t *aux2 = zhash_new ();
    zhash_autofree (aux2);
    zhash_insert (aux2, "type", (void *) "row");
    zhash_insert (aux2, "priority", (void *) "P2");
    zmsg_t *m = fty_proto_encode_asset (aux2,
                    "test",
                    FTY_PROTO_ASSET_OP_UPDATE,
                    NULL);
    assert (m);
    zhash_destroy (&aux2);
    int rv = mlm_client_send (asset_producer, "row.@test", &m);
    assert ( rv == 0 );

    zclock_sleep (6000);

    char *average_humidity = s_readall ((std::string ("src") + "/average.humidity@test.rule").c_str ());
    assert (average_humidity);
    char *average_temperature = s_readall ((std::string ("src") + "/average.temperature@test.rule").c_str ());
    assert (average_temperature);

    zstr_free (&average_humidity);
    zstr_free (&average_temperature);
    // TODO: now inapplicable rules should be deleted in the future
    /* realpower_default =  s_readall ((std::string ("src") + "/realpower.default@test.rule").c_str ());
    phase_imbalance = s_readall ((std::string ("src") + "/phase.imbalance@test.rule").c_str ());
    assert (realpower_default == NULL && phase_imbalance == NULL); */

    int ttl = 60;
    zclock_sleep (3*ttl);
    m = fty_proto_encode_metric (
        NULL, ::time (NULL), ttl, "average.temperature", "test", "1000", "C");
    assert (m);
    rv = mlm_client_send (producer, "average.temperature@test", &m);
    assert ( rv == 0 );

    zmsg_t *recv = mlm_client_recv (consumer);
    assert ( recv != NULL );
    assert ( is_fty_proto (recv));
    fty_proto_t *brecv = fty_proto_decode (&recv);
    assert (streq (fty_proto_rule (brecv), "average.temperature@test"));
    assert (streq (fty_proto_name (brecv), "test"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    if ( verbose ) {
            zsys_debug ("Alert was sent: SUCCESS");
        }
    fty_proto_destroy (&brecv);
    }
    // # 28 update the created asset to something completely different, check that alert is resolved
    // and that we deleted old rules and created new

    /* {
     * zhash_t *aux3 = zhash_new ();
    zhash_autofree (aux3);
    zhash_insert (aux3, "type", (void *) "device");
    zhash_insert (aux3, "subtype", (void *) "epdu");
    m = fty_proto_encode_asset (aux3,
                    "test",
                    FTY_PROTO_ASSET_OP_UPDATE,
                    NULL);
    assert (m);
    rv = mlm_client_send (asset_producer, "device.epdu@test", &m);
    assert ( rv == 0 );

    poller = zpoller_new (mlm_client_msgpipe (consumer), NULL);
    assert (poller);
    which = zpoller_wait (poller, 3*ttl2);
    assert ( which != NULL );
    recv = mlm_client_recv (consumer);
    assert ( recv != NULL );
    assert ( is_fty_proto (recv));
    if ( verbose ) {
            brecv = fty_proto_decode (&recv);
            assert (streq (fty_proto_rule (brecv), "average.temperature@test.rule"));
            assert (streq (fty_proto_name (brecv), "test"));
            assert (streq (fty_proto_state (brecv), "RESOLVED"));
            assert (streq (fty_proto_severity (brecv), "CRITICAL"));
            fty_proto_destroy (&brecv);
            zsys_debug ("Alert was sent: SUCCESS");
        }
    int ttl3 = fty_proto_ttl (brecv);
    assert (ttl3 != -1);
    zmsg_destroy (&recv);
    zpoller_destroy (&poller);

    char *average_humidity2 = s_readall ((std::string ("src/testrules") + "/average.humidity@test.rule").c_str ());
    char *average_temperature2 = s_readall ((std::string ("src/testrules") + "/average.temperature@test.rule").c_str ());
    char *realpower_default2 =  s_readall ((std::string ("src/testrules") + "/realpower.default@test.rule").c_str ());
    char *phase_imbalance2 = s_readall ((std::string ("src/testrules") + "/phase.imbalance@test.rule").c_str ());
    assert (average_humidity2 == NULL && average_temperature2 == NULL && realpower_default2 == NULL && phase_imbalance2 == NULL);
    zstr_free (&average_humidity2);
    zstr_free (&average_temperature2);
    zstr_free (&realpower_default2);
    zstr_free (&phase_imbalance2);

    char *load_1phase = s_readall ((std::string ("src/testrules") + "/load.input_1phase@test.rule").c_str ());
    assert (load_1phase);
    char *load_3phase = s_readall ((std::string ("src/testrules") + "/load.input_3phase@test.rule").c_str ());
    assert (load_3phase);
    char *section_load =  s_readall ((std::string ("src/testrules") + "/section_load@test.rule").c_str ());
    assert (section_load);
    char *phase_imbalance3 = s_readall ((std::string ("src/testrules") + "/phase.imbalance@test.rule").c_str ());
    assert (phase_imbalance);
    char *voltage_1phase = s_readall ((std::string ("src/testrules") + "/voltage.input_1phase@test.rule").c_str ());
    assert (voltage_1phase);
    char *voltage_3phase = s_readall ((std::string ("src/testrules") + "/voltage.input_3phase@test.rule").c_str ());
    assert (voltage_3phase);

    zstr_free (&load_1phase);
    zstr_free (&load_3phase);
    zstr_free (&section_load);
    zstr_free (&phase_imbalance3);
    zstr_free (&voltage_1phase);
    zstr_free (&voltage_3phase); 
    } */

    // # 29.1 force the alert for the updated device

    /* {
     * m = fty_proto_encode_metric (
                        NULL, "phase.imbalance", "test", "50", "%", 0);
    assert (m);
    rv = mlm_client_send (producer, "phase.imbalance@test", &m);
    assert ( rv == 0 );

    recv = mlm_client_recv (consumer);
    assert (recv);
    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (brecv);
    int ttl4 = fty_proto_ttl (brecv);
    assert (ttl4 != -1);
    assert (streq (fty_proto_rule (brecv), "phase.imbalance@test.rule"));
    assert (streq (fty_proto_name (brecv), "test"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    fty_proto_destroy (&brecv); */

    // # 29.2 delete the created asset, check that we deleted the rules and all alerts are resolved

    /* m = fty_proto_encode_asset (aux3,
                        "test",
                        FTY_PROTO_ASSET_OP_DELETE,
                        NULL);
    assert (m);
    rv = mlm_client_send (asset_producer, "device.epdu@test", &m);
    assert ( rv == 0 );

    load_1phase = s_readall ((std::string ("src/testrules") + "/load.input_1phase@test.rule").c_str ());
    load_3phase = s_readall ((std::string ("src/testrules") + "/load.input_3phase@test.rule").c_str ());
    section_load =  s_readall ((std::string ("src/testrules") + "/section_load@test.rule").c_str ());
    phase_imbalance3 = s_readall ((std::string ("src/testrules") + "/phase.imbalance@test.rule").c_str ());
    voltage_1phase = s_readall ((std::string ("src/testrules") + "/voltage.input_1phase@test.rule").c_str ());
    voltage_3phase = s_readall ((std::string ("src/testrules") + "/voltage.input_3phase@test.rule").c_str ());

    assert (load_1phase == NULL && load_3phase == NULL && section_load == NULL && phase_imbalance3 == NULL && voltage_1phase == NULL && voltage_3phase == NULL);

    zstr_free (&load_1phase);
    zstr_free (&load_3phase);
    zstr_free (&section_load);
    zstr_free (&phase_imbalance3);
    zstr_free (&voltage_1phase);
    zstr_free (&voltage_3phase);

    poller = zpoller_new (mlm_client_msgpipe (consumer), NULL);
    assert (poller);
    which = zpoller_wait (poller, 3*ttl4);
    assert ( which != NULL );
    recv = mlm_client_recv (consumer);
    assert ( recv != NULL );
    assert ( is_fty_proto (recv));
    if ( verbose ) {
            brecv = fty_proto_decode (&recv);
            assert (streq (fty_proto_rule (brecv), "phase.imbalance@test.rule"));
            assert (streq (fty_proto_name (brecv), "test"));
            assert (streq (fty_proto_state (brecv), "RESOLVED"));
            assert (streq (fty_proto_severity (brecv), "CRITICAL"));
            fty_proto_destroy (&brecv);
            zsys_debug ("Alert was sent: SUCCESS");
    }
    zmsg_destroy (&recv);
    zpoller_destroy (&poller);
    }
    */
    // Test case #20 update some rule (type: pattern)
    {
    zmsg_t *rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char *pattern_rule = s_readall ("testrules/pattern.rule");
    assert (pattern_rule);
    zmsg_addstrf (rule, "%s", pattern_rule);
    zmsg_addstrf (rule, "%s", "warranty2");
    zstr_free (&pattern_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    zmsg_t *recv = mlm_client_recv (ui);
    assert (zmsg_size (recv) == 2);
    char *foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);

    // recieve an alert
    recv = mlm_client_recv (consumer);
    assert ( recv != NULL );
    assert (is_fty_proto (recv));
    fty_proto_t *brecv = fty_proto_decode (&recv);
    fty_proto_destroy (&brecv);
    }

    zclock_sleep (3000);
    zactor_destroy (&ag_configurator);
    zactor_destroy (&ag_server);
    mlm_client_destroy (&asset_producer);
    mlm_client_destroy (&ui);
    mlm_client_destroy (&consumer);
    mlm_client_destroy (&producer);
    zactor_destroy (&server);

    static const std::vector <std::string> strings {
        "ŽlUťOUčKý kůň",
        "\u017dlu\u0165ou\u010dk\xc3\xbd K\u016f\xc5\x88",
        "Žluťou\u0165ký kůň",
        "ŽLUťou\u0165Ký kůň",
        "Ka\xcc\x81rol",
        "K\xc3\xa1rol",
        "супер test",
        "\u0441\u0443\u043f\u0435\u0440 Test"

    };

    assert (utf8eq (strings[0], strings[1]) == 1);
    assert (utf8eq (strings[0], strings[2]) == 0);
    assert (utf8eq (strings[1], strings[2]) == 0);
    assert (utf8eq (strings[2], strings[3]) == 1);
    assert (utf8eq (strings[4], strings[5]) == 0);
    assert (utf8eq (strings[6], strings[7]) == 1);

    //  @end
    printf ("OK\n");
}
