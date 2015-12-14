/*  =========================================================================
    bios_alert_generator_server - Actor evaluating rules

    Copyright (C) 2014 - 2015 Eaton                                        
                                                                           
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
    bios_alert_generator_server - Actor evaluating rules
@discuss
@end
*/
#include <string.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include <fstream>
#include <malamute.h>
#include <bios_proto.h>
#include <math.h>

#include "rule.h"
#include "normalrule.h"
#include "thresholdrulesimple.h"
#include "thresholdrulecomplex.h"
#include "regexrule.h"

#include "alertconfiguration.h"

//http://en.cppreference.com/w/cpp/language/typeid
//The header <typeinfo> must be included before using typeid
#include <typeinfo>


#define METRICS_STREAM "METRICS"
#define RULES_SUBJECT "rfc-evaluator-rules"
#define ACK_SUBJECT "rfc-alerts-acknowledge"

#include "../include/alert_agent.h"
#include "alert_agent_classes.h"

static void
list_rules(
    mlm_client_t *client,
    const char *type,
    AlertConfiguration &ac)
{
    zsys_info ("Give me the list of rules with type = '%s'", type);
    std::vector<Rule*> rules;

    if (streq (type,"all")) {
        rules = ac.getRules();
    }
    else if (streq (type,"threshold")) {
        // actually we have 2 slightly different threshold rules
        rules = ac.getRulesByType (typeid (ThresholdRuleSimple));
        std::vector<Rule *> rules1 = ac.getRulesByType (typeid (ThresholdRuleComplex));
        rules.insert (rules.begin(), rules1.begin(), rules1.end());
    }
    else if (streq (type,"single")) {
        rules = ac.getRulesByType (typeid (NormalRule));
    }
    else if (streq (type,"pattern")) {
        rules = ac.getRulesByType (typeid (RegexRule));
    }
    else {
        //invalid type
        zmsg_t *reply = zmsg_new ();
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "INVALID_TYPE");
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zmsg_destroy (&reply);
        return;
    }
    zmsg_t *reply = zmsg_new ();
    assert (reply);
    zmsg_addstr (reply, "LIST");
    zmsg_addstr (reply, type);
    for (auto rule: rules) {
        zmsg_addstr (reply, rule->getJsonRule().c_str());
    }
    mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
    zmsg_destroy( &reply );
}

static void
get_rule(
    mlm_client_t *client,
    const char *name,
    AlertConfiguration &ac)
{
    zsys_info ("Give me the detailes about rule with rule_name = '%s'", name);
    Rule *rule = ac.getRuleByName(name);
    if(!rule) {
        // rule doesn't exist
        zmsg_t *reply = zmsg_new ();
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "NOT_FOUND");
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zmsg_destroy (&reply);
        return;
    }
    zmsg_t *reply = zmsg_new ();
    assert (reply);
    zmsg_addstr (reply, "OK");
    zmsg_addstr (reply, rule->getJsonRule().c_str());
    mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
    zmsg_destroy( &reply );
}


static std::string
makeActionList(
    const std::vector <std::string> &actions)
{
    std::ostringstream s;
    for (const auto& oneAction : actions) {
        if (&oneAction != &actions[0]) {
            s << "/";
        }
        s << oneAction;
    }
    return s.str();
}

static void
send_alerts(
    mlm_client_t *client,
    const std::vector <PureAlert> &alertsToSend,
    const std::string &rule_name)
{
    for ( const auto &alert : alertsToSend )
    {
        zmsg_t *msg = bios_proto_encode_alert (
            NULL,
            rule_name.c_str(),
            alert._element.c_str(),
            alert._status.c_str(),
            alert._severity.c_str(),
            alert._description.c_str(),
            -1,
            makeActionList(alert._actions).c_str()
        );
        if( msg ) {
            std::string atopic = rule_name + "/"
                + alert._severity + "@"
                + alert._element;
            mlm_client_send (client, atopic.c_str(), &msg);
        }
    }
}

static void
send_alerts(
    mlm_client_t *client,
    const std::vector <PureAlert> &alertsToSend,
    const Rule *rule)
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
    Rule* newRule = NULL;
    int rv = ac.addRule (f, newSubjectsToSubscribe, alertsToSend, &newRule);
    zmsg_t *reply = zmsg_new ();
    switch (rv) {
    case -2:
        // rule exists
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "ALREADY_EXISTS");
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zmsg_destroy (&reply);
        return;
    case 0:
        // rule was created succesfully
        zsys_info ("newsubjects count = %d", newSubjectsToSubscribe.size() );
        zsys_info ("alertsToSend count = %d", alertsToSend.size() );
        for ( const auto &interestedSubject : newSubjectsToSubscribe ) {
            mlm_client_set_consumer(client, METRICS_STREAM, interestedSubject.c_str());
            zsys_info("Registered to receive '%s'\n", interestedSubject.c_str());
        }

        // send a reply back
        zmsg_addstr (reply, "OK");
        zmsg_addstr (reply, json_representation);
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zmsg_destroy (&reply);
        // send updated alert
        send_alerts (client, alertsToSend, newRule);
        return;
    default:
        // error during the rule creation
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_JSON");
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zmsg_destroy (&reply);
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
    Rule* newRule = NULL;
    if ( ! ac.haveRule (rule_name) )
    {
        // ERROR rule doesn't exist
        zmsg_t *reply = zmsg_new ();
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "NOT_FOUND");
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zmsg_destroy (&reply);
        return;
    }

    int rv = ac.updateRule (f, rule_name, newSubjectsToSubscribe, alertsToSend, &newRule);
    if ( rv != 0 )
    {
        // ERROR during the rule updating
        zmsg_t *reply = zmsg_new ();
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "RULE_HAS_ERRORS");
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zmsg_destroy (&reply);
        return;

    }
    // rule was updated succesfully
    zsys_info ("newsubjects count = %d", newSubjectsToSubscribe.size() );
    zsys_info ("alertsToSend count = %d", alertsToSend.size() );
    for ( const auto &interestedSubject : newSubjectsToSubscribe ) {
        mlm_client_set_consumer(client, METRICS_STREAM, interestedSubject.c_str());
        zsys_info("Registered to receive '%s'\n", interestedSubject.c_str());
    }

    // send a reply back
    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "OK");
    zmsg_addstr (reply, json_representation);
    mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
    zmsg_destroy (&reply);
    // send updated alert
    send_alerts (client, alertsToSend, newRule);
}


static void
change_state(
    mlm_client_t *client,
    const char *rule_name,
    const char *element_name,
    const char *new_state,
    AlertConfiguration &ac)
{
    if ( !ac.haveRule (rule_name) )
    {
        // ERROR rule doesn't exist
        zmsg_t *reply = zmsg_new ();
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "NOT_FOUND");
        mlm_client_sendto (client, mlm_client_sender(client), ACK_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zmsg_destroy (&reply);
        return;
    }

    PureAlert alertToSend;
    int rv = ac.updateAlertState (rule_name, element_name, new_state, alertToSend);
    if ( rv != 0 )
    {
        // ERROR during the rule updating
        zmsg_t *reply = zmsg_new ();
        zmsg_addstr (reply, "ERROR");
        if ( rv == -5 || rv == -2 || rv == -1 ) {
            zmsg_addstr (reply, "BAD_STATE");
        }
        if ( rv == -4 ) {
            zmsg_addstr (reply, "NOT_FOUND");
        }
        else {
            zmsg_addstr (reply, "CANT_CHANGE_ALERT_STATE");
        }
        mlm_client_sendto (client, mlm_client_sender(client), ACK_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zmsg_destroy (&reply);
        return;
    }
    // send a reply back
    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "OK");
    zmsg_addstr (reply, rule_name);
    zmsg_addstr (reply, element_name);
    zmsg_addstr (reply, new_state);
    mlm_client_sendto (client, mlm_client_sender(client), ACK_SUBJECT, mlm_client_tracker (client), 1000, &reply);
    zmsg_destroy (&reply);
    // send updated alert
    send_alerts (client, {alertToSend}, rule_name);
}


static void
evaluate_metric(
    mlm_client_t *client,
    const MetricInfo &triggeringMetric,
    const MetricList &knownMetricValues,
    AlertConfiguration &ac)
{
    // Go through all known rules, and try to evaluate them
    for ( const auto &rule : ac.getRules() ) {
        try {
            zsys_info(" # Check rule '%s'", rule->name().c_str());
            if ( !rule->isTopicInteresting (triggeringMetric.generateTopic())) {
                zsys_info (" ### Metric is not interesting for this rule");
                continue;
            }

            PureAlert *pureAlert = NULL;
            // TODO memory leak
            int rv = rule->evaluate (knownMetricValues, &pureAlert);
            if ( rv != 0 ) {
                zsys_info (" ### Cannot evaluate the rule '%s'", rule->name().c_str());
                continue;
            }
            zsys_info (" ### Metric was evaluated");

            auto alertToSend = ac.updateAlert (rule, *pureAlert);
            if ( alertToSend == NULL ) {
                zsys_info(" ### alert updated, nothing to send");
                // nothing to send
                continue;
            }
            send_alerts (client, {*alertToSend}, rule);
        }
        catch ( const std::exception &e) {
            zsys_error ("CANNOT evaluate rule, because '%s'", e.what());
        }
    }
}


void
bios_alert_generator_server (zsock_t *pipe, void* args)
{
    // need to track incoming measurements
    MetricList cache;
    AlertConfiguration alertConfiguration;
    bool verbose = false;

    char *name = (char*) args;

    mlm_client_t *client = mlm_client_new ();

    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (client), NULL);

    zsock_signal (pipe, 0);

    while (!zsys_interrupted) {

        void *which = zpoller_wait (poller, -1);
        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            char *cmd = zmsg_popstr (msg);

            if (streq (cmd, "$TERM")) {
                zstr_free (&cmd);
                zmsg_destroy (&msg);
                goto exit;
            }
            else
            if (streq (cmd, "VERBOSE")) {
                verbose = true;
                zmsg_destroy (&msg);
            }
            else
            if (streq (cmd, "CONNECT")) {
                char* endpoint = zmsg_popstr (msg);
                int rv = mlm_client_connect (client, endpoint, 1000, name);
                if (rv == -1)
                    zsys_error ("%s: can't connect to malamute endpoint '%s'", name, endpoint);
                zstr_free (&endpoint);
            }
            else
            if (streq (cmd, "PRODUCER")) {
                char* stream = zmsg_popstr (msg);
                int rv = mlm_client_set_producer (client, stream);
                if (rv == -1)
                    zsys_error ("%s: can't set producer on stream '%s'", name, stream);
                zstr_free (&stream);
            }
            else
            if (streq (cmd, "CONSUMER")) {
                char* stream = zmsg_popstr (msg);
                char* pattern = zmsg_popstr (msg);
                int rv = mlm_client_set_consumer (client, stream, pattern);
                if (rv == -1)
                    zsys_error ("%s: can't set consumer on stream '%s', '%s'", name, stream, pattern);
                zstr_free (&pattern);
                zstr_free (&stream);
            }
            if (streq (cmd, "CONFIG")) {
                char* filename = zmsg_popstr (msg);

                // Read initial configuration
                alertConfiguration.setPath(filename);
                std::set <std::string> subjectsToConsume = alertConfiguration.readConfiguration();
                zsys_info ("subjectsToConsume count: %d\n", subjectsToConsume.size());

                // Subscribe to all subjects
                for ( const auto &interestedSubject : subjectsToConsume ) {
                    int rv = mlm_client_set_consumer(client, METRICS_STREAM, interestedSubject.c_str());
                    if (rv == -1)
                        zsys_error ("%s: can't set consumer on stream '%s', '%s'", name, METRICS_STREAM, interestedSubject.c_str());
                    if (verbose)
                        zsys_info("%s: Registered to receive '%s'\n", name, interestedSubject.c_str());
                }
                zstr_free (&filename);
            }
            zstr_free (&cmd);
            zmsg_destroy (&msg);
            continue;
        }

        // This agent is a reactive agent, it reacts only on messages
        // and doesn't do anything if there is no messages
        zmsg_t *zmessage = mlm_client_recv (client);
        if ( zmessage == NULL ) {
            continue;
        }
        std::string topic = mlm_client_subject(client);
        zsys_info("Got message '%s'", topic.c_str());
        // There are two possible inputs and they come in different ways
        // from the stream  -> metrics
        // from the mailbox -> rules
        //                  -> request for rule list
        // but even so we try to decide according what we got, not from where
        if( is_bios_proto(zmessage) ) {
            bios_proto_t *bmessage = bios_proto_decode(&zmessage);
            if( ! bmessage ) {
                zsys_info ("cannot decode message, ignoring\n");
                continue;
            }
            if ( bios_proto_id(bmessage) == BIOS_PROTO_METRIC )  {
                // process as metric message
                const char *type = bios_proto_type(bmessage);
                const char *element_src = bios_proto_element_src(bmessage);
                const char *value = bios_proto_value(bmessage);
                const char *unit = bios_proto_unit(bmessage);
                int64_t timestamp = bios_proto_time(bmessage);
                if( timestamp <= 0 ) timestamp = time(NULL);

                char *end;
                double dvalue = strtod (value, &end);
                if (errno == ERANGE) {
                    errno = 0;
                    zsys_info ("cannot convert value to double, ignore message\n");
                    continue;
                }
                else if (end == value || *end != '\0') {
                    zsys_info ("cannot convert value to double, ignore message\n");
                    continue;
                }

                zsys_info("Got message '%s' with value %s\n", topic.c_str(), value);

                // Update cache with new value
                MetricInfo m (element_src, type, unit, dvalue, timestamp, "");
                bios_proto_destroy(&bmessage);
                cache.addMetric (m);
                cache.removeOldMetrics();
                evaluate_metric(client, m, cache, alertConfiguration);
            }
        }
        else if ( streq (mlm_client_command (client), "MAILBOX DELIVER" ) )
        {
            // According RFC we expect here a messages
            // with the topics ACK_SUBJECT and RULE_SUBJECT
            if ( streq (mlm_client_subject (client), RULES_SUBJECT) )
            {
                // Here we can have:
                //  * new rule
                //  * request for list of rules
                //  * get detailed info about the rule
                char *command = zmsg_popstr (zmessage);
                char *param = zmsg_popstr (zmessage);
                if (command && param) {
                    if (streq (command, "LIST")) {
                        list_rules (client, param, alertConfiguration);
                    }
                    else if (streq (command, "GET")) {
                        get_rule (client, param, alertConfiguration);
                    }
                    else if (streq (command, "ADD") ) {
                        if ( zmsg_size(zmessage) == 0 ) {
                            // ADD/json
                            add_rule (client, param, alertConfiguration);
                        }
                        else
                        {
                            // ADD/json/old_name
                            char *param1 = zmsg_popstr (zmessage);
                            update_rule (client, param, param1, alertConfiguration);
                            if (param1) free (param1);
                        }
                    }
                }
                zstr_free (&command);
                zstr_free (&param);
            }
            else
            if ( streq (mlm_client_subject (client), ACK_SUBJECT) )
            {
                // Here we can have:
                //  * change acknowlegment state of the alert
                char *param1 = zmsg_popstr (zmessage); // rule name
                char *param2 = zmsg_popstr (zmessage); // element name
                char *param3 = zmsg_popstr (zmessage); // state
                if ( !param1 || !param2 || !param3 ) {
                    zsys_info ("Ignore it. Unexpected message format");
                }
                else {
                    change_state (client, param1, param2, param3, alertConfiguration);
                }

                zstr_free (&param1);
                zstr_free (&param2);
                zstr_free (&param2);
            }
            else
                zsys_info ("Ignore it. Unexpected topic for MAILBOX message: '%s'", mlm_client_subject (client) );
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

    char *ret = (char*) calloc (1, fsize * sizeof (char));
    if (!ret)
        return NULL;

    size_t r = fread((void*) ret, 1, fsize, fp);
    if (r == fsize)
        return ret;

    free (ret);
    return NULL;
}

void
bios_alert_generator_server_test (bool verbose)
{
    printf (" * bios_alert_generator_server: ");
    if (verbose)
        printf ("\n");

    int r = system ("rm -f src/*.rule");
    assert (r == 0); // to make gcc @ CentOS 7 happy

    //  @selftest
    static const char* endpoint = "inproc://bios-ag-server-test";

    zactor_t *server = zactor_new (mlm_server, (void*) "Malamute");
    zstr_sendx (server, "BIND", endpoint, NULL);
    if (verbose)
        zstr_send (server, "VERBOSE");

    mlm_client_t *producer = mlm_client_new ();
    mlm_client_connect (producer, endpoint, 1000, "producer");
    mlm_client_set_producer (producer, "METRICS");

    mlm_client_t *consumer = mlm_client_new ();
    mlm_client_connect (consumer, endpoint, 1000, "consumer");
    mlm_client_set_consumer (consumer, "ALERTS", ".*");

    mlm_client_t *ui = mlm_client_new ();
    mlm_client_connect (ui, endpoint, 1000, "UI");

    zactor_t *ag_server = zactor_new (bios_alert_generator_server, (void*) "alert-agent");
    if (verbose)
        zstr_send (ag_server, "VERBOSE");
    zstr_sendx (ag_server, "CONNECT", endpoint, NULL);
    zstr_sendx (ag_server, "PRODUCER", "ALERTS", NULL);
    zstr_sendx (ag_server, "CONFIG", "src/", NULL);
    zclock_sleep (500);   //THIS IS A HACK TO SETTLE DOWN THINGS

    // Test case #1: list w/o rules
    zmsg_t *command = zmsg_new ();
    zmsg_addstrf (command, "%s", "LIST");
    zmsg_addstrf (command, "%s", "all");
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &command);

    zmsg_t *recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    char * foo = zmsg_popstr (recv);
    assert (streq (foo, "LIST"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "all"));
    zstr_free (&foo);
    zmsg_destroy (&recv);

    // Test case #2: add new rule
    zmsg_t *rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char* simplethreshold_rule = s_readall ("testrules/simplethreshold.rule");
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

    // Test case #3: list rules
    command = zmsg_new ();
    zmsg_addstrf (command, "%s", "LIST");
    zmsg_addstrf (command, "%s", "all");
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &command);

    recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 3);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "LIST"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "all"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);

    // Test case #4: list rules - not yet stored type
    command = zmsg_new ();
    zmsg_addstrf (command, "%s", "LIST");
    zmsg_addstrf (command, "%s", "single");
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &command);

    recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "LIST"));
    zstr_free (&foo);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "single"));
    zstr_free (&foo);
    zmsg_destroy (&recv);

    //Test case #5: generate alert - below the treshold
    zmsg_t *m = bios_proto_encode_metric (
            NULL, "abc", "fff", "20", "X", 0);
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);

    assert (is_bios_proto (recv));
    bios_proto_t *brecv = bios_proto_decode (&recv);
    assert (streq (bios_proto_rule (brecv), "simplethreshold"));
    assert (streq (bios_proto_element_src (brecv), "fff"));
    assert (streq (bios_proto_state (brecv), "ACTIVE"));
    assert (streq (bios_proto_severity (brecv), "CRITICAL"));
    bios_proto_destroy (&brecv);

    // Test case #6: generate alert - resolved
    m = bios_proto_encode_metric (
            NULL, "abc", "fff", "42", "X", 0);
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);

    assert (is_bios_proto (recv));
    brecv = bios_proto_decode (&recv);
    assert (streq (bios_proto_rule (brecv), "simplethreshold"));
    assert (streq (bios_proto_element_src (brecv), "fff"));
    assert (streq (bios_proto_state (brecv), "RESOLVED"));
    bios_proto_destroy (&brecv);

    // Test case #6: generate alert - high warning
    m = bios_proto_encode_metric (
            NULL, "abc", "fff", "52", "X", 0);
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);

    assert (recv);
    assert (is_bios_proto (recv));
    brecv = bios_proto_decode (&recv);
    assert (brecv);
    assert (streq (bios_proto_rule (brecv), "simplethreshold"));
    assert (streq (bios_proto_element_src (brecv), "fff"));
    assert (streq (bios_proto_state (brecv), "ACTIVE"));
    assert (streq (bios_proto_severity (brecv), "WARNING"));
    bios_proto_destroy (&brecv);

    // Test case #7: generate alert - high critical
    m = bios_proto_encode_metric (
            NULL, "abc", "fff", "62", "X", 0);
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);

    assert (recv);
    assert (is_bios_proto (recv));
    brecv = bios_proto_decode (&recv);
    assert (brecv);
    assert (streq (bios_proto_rule (brecv), "simplethreshold"));
    assert (streq (bios_proto_element_src (brecv), "fff"));
    assert (streq (bios_proto_state (brecv), "ACTIVE"));
    assert (streq (bios_proto_severity (brecv), "CRITICAL"));
    bios_proto_destroy (&brecv);

    // Test case #8: generate alert - resolved again
    m = bios_proto_encode_metric (
            NULL, "abc", "fff", "42", "X", 0);
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);

    assert (recv);
    assert (is_bios_proto (recv));
    brecv = bios_proto_decode (&recv);
    assert (brecv);
    assert (streq (bios_proto_rule (brecv), "simplethreshold"));
    assert (streq (bios_proto_element_src (brecv), "fff"));
    assert (streq (bios_proto_state (brecv), "RESOLVED"));
    bios_proto_destroy (&brecv);

    // Test case #9: generate alert - high again
    m = bios_proto_encode_metric (
            NULL, "abc", "fff", "62", "X", 0);
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);

    assert (recv);
    assert (is_bios_proto (recv));
    brecv = bios_proto_decode (&recv);
    assert (brecv);
    assert (streq (bios_proto_rule (brecv), "simplethreshold"));
    assert (streq (bios_proto_element_src (brecv), "fff"));
    assert (streq (bios_proto_state (brecv), "ACTIVE"));
    assert (streq (bios_proto_severity (brecv), "CRITICAL"));
    bios_proto_destroy (&brecv);

    // Test case #10: test alert acknowledge
    rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "simplethreshold");
    zmsg_addstrf (rule, "%s", "fff");
    zmsg_addstrf (rule, "%s", "ACK-PAUSE");
    mlm_client_sendto (ui, "alert-agent", "rfc-alerts-acknowledge", NULL, 1000, &rule);

    char *subject, *status, *rule_name, *element_name, *new_state;
    r = mlm_client_recvx (ui, &subject, &status, &rule_name, &element_name, &new_state, NULL);
    assert (r != -1);
    assert (streq (status, "OK"));
    assert (streq (rule_name, "simplethreshold"));
    assert (streq (element_name, "fff"));
    assert (streq (new_state, "ACK-PAUSE"));
    zstr_free (&subject);
    zstr_free (&status);
    zstr_free (&rule_name);
    zstr_free (&element_name);
    zstr_free (&new_state);

    // Test case #11: generate alert - high again - after ACK-PAUSE
    m = bios_proto_encode_metric (
            NULL, "abc", "fff", "62", "X", 0);
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);

    assert (recv);
    assert (is_bios_proto (recv));
    brecv = bios_proto_decode (&recv);
    assert (brecv);
    assert (streq (bios_proto_rule (brecv), "simplethreshold"));
    assert (streq (bios_proto_element_src (brecv), "fff"));
    assert (streq (bios_proto_state (brecv), "ACK-PAUSE"));
    assert (streq (bios_proto_severity (brecv), "CRITICAL"));
    bios_proto_destroy (&brecv);

    // Test case #12: generate alert - normal - after ACK-PAUSE
    m = bios_proto_encode_metric (
            NULL, "abc", "fff", "42", "X", 0);
    mlm_client_send (producer, "abc@fff", &m);

    recv = mlm_client_recv (consumer);

    assert (recv);
    assert (is_bios_proto (recv));
    brecv = bios_proto_decode (&recv);
    assert (brecv);
    assert (streq (bios_proto_rule (brecv), "simplethreshold"));
    assert (streq (bios_proto_element_src (brecv), "fff"));
    assert (streq (bios_proto_state (brecv), "ACK-PAUSE")); //XXX: should not there be NEW?
    bios_proto_destroy (&brecv);

    zactor_destroy (&ag_server);
    mlm_client_destroy (&ui);
    mlm_client_destroy (&consumer);
    mlm_client_destroy (&producer);
    zactor_destroy (&server);
    //  @end

    printf ("OK\n");
}
