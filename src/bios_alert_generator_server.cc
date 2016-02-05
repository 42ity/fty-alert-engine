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
#include <functional>

int agent_alert_verbose = 0;

#define zsys_debug1(...) \
    do { if (agent_alert_verbose) zsys_debug (__VA_ARGS__); } while (0);

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
    zsys_debug1 ("\t--- entering ---");
    zsys_debug1 ("type == '%s'", type);
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
        zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
                mlm_client_sender (client), RULES_SUBJECT);
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");
        zsys_debug1 ("\t--- leaving ---");
        return;
    }
    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "LIST");
    zmsg_addstr (reply, type);
    // std::vector <
    //  std::pair <
    //      RulePtr,
    //      std::vector<PureAlert>
    //      >
    // >
    zsys_debug1 ("number of all rules = '%zu'", ac.size ());
    for (const auto &i: ac) {
        const auto& rule = i.first;
        if (!filter_f(rule->whoami ())) {
            zsys_debug1 ("Skipping rule  = '%s'", rule->name().c_str());
            continue;
        }
        zsys_debug1 ("Adding rule  = '%s'", rule->name().c_str());
        zmsg_addstr (reply, rule->getJsonRule().c_str());
    }
    zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
            mlm_client_sender (client), RULES_SUBJECT);
    mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
    zsys_debug1 ("mlm_client_sendto () finished");
    zsys_debug1 ("\t--- leaving ---");
}

static void
get_rule(
    mlm_client_t *client,
    const char *name,
    AlertConfiguration &ac)
{
    assert (name != NULL);
    zsys_debug1 ("\t--- entering ---");
    zsys_debug1 ("name = '%s'", name);
    zsys_debug1 ("number of all rules = '%zu'", ac.size ());
    for (const auto& i: ac) {
        const auto &rule = i.first;
        if (rule->hasSameNameAs (name))
        {
            zsys_debug1 ("found");
            zmsg_t *reply = zmsg_new ();
            zmsg_addstr (reply, "OK");
            zmsg_addstr (reply, rule->getJsonRule().c_str());

            zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
                mlm_client_sender (client), RULES_SUBJECT);
            mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            zsys_debug1 ("mlm_client_sendto () finished");

            zsys_debug1 ("\t--- leaving ---");
            return;
        }
    }

    zsys_debug1 ("not found");
    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "ERROR");
    zmsg_addstr (reply, "NOT_FOUND");

    zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
        mlm_client_sender (client), RULES_SUBJECT);
    mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
    zsys_debug1 ("mlm_client_sendto () finished");

    zsys_debug1 ("\t--- leaving ---");
    return;
}


static std::string
makeActionList(
    const std::vector <std::string> &actions)
{
    zsys_debug1 ("\t--- entering ---");
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
    zsys_debug1 ("\t--- leaving ---");
    return s;
}

static void
send_alerts(
    mlm_client_t *client,
    const std::vector <PureAlert> &alertsToSend,
    const std::string &rule_name)
{
    zsys_debug1 ("\t--- entering ---");
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
            zsys_debug1 ("mlm_client_send (subject = '%s')", atopic.c_str());
            mlm_client_send (client, atopic.c_str(), &msg);
            zsys_debug1 ("mlm_client_send () finished.");
        }
    }
    zsys_debug1 ("\t--- leaving ---");
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
    zsys_debug1 ("\t--- entering ---");
    std::istringstream f(json_representation);
    std::set <std::string> newSubjectsToSubscribe;
    std::vector <PureAlert> alertsToSend;
    AlertConfiguration::iterator new_rule_it;
    int rv = ac.addRule (f, newSubjectsToSubscribe, alertsToSend, new_rule_it);
    zmsg_t *reply = zmsg_new ();
    switch (rv) {
    case -2:
        // rule exists
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "ALREADY_EXISTS");

        zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
            mlm_client_sender (client), RULES_SUBJECT);
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");

        zsys_debug1 ("\t--- leaving ---");
        return;
    case 0:
        // rule was created succesfully
        zsys_debug1 ("newsubjects count = %d", newSubjectsToSubscribe.size() );
        zsys_debug1 ("alertsToSend count = %d", alertsToSend.size() );
        for ( const auto &interestedSubject : newSubjectsToSubscribe ) {
            zsys_debug1 ("Registering to receive '%s'", interestedSubject.c_str());
            mlm_client_set_consumer(client, METRICS_STREAM, interestedSubject.c_str());
            zsys_debug1("Registering finished");
        }

        // send a reply back
        zmsg_addstr (reply, "OK");
        zmsg_addstr (reply, json_representation)
            ;
        zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
            mlm_client_sender (client), RULES_SUBJECT);
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");

        // send updated alert
        zsys_debug1 ("send_alerts () started");
        send_alerts (client, alertsToSend, new_rule_it->first);
        zsys_debug1 ("send_alerts () finished");
        zsys_debug1 ("\t--- leaving ---");
        return;
    case -5:
        // error during the rule creation (lua)
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_LUA");

        zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
            mlm_client_sender (client), RULES_SUBJECT);
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");

        zsys_debug1 ("\t--- leaving ---");
        return;
    case -6:
    {
        // error during the rule creation (lua)
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "Internal error - operating with storate/disk failed.");

        zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
            mlm_client_sender (client), RULES_SUBJECT);
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");

        zsys_debug1 ("\t--- leaving ---");
        return;
    }
    default:
        // error during the rule creation
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_JSON");

        zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
            mlm_client_sender (client), RULES_SUBJECT);
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");

        zsys_debug1 ("\t--- leaving ---");
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
    zsys_debug1 ("\t--- entering ---");
    std::istringstream f(json_representation);
    std::set <std::string> newSubjectsToSubscribe;
    std::vector <PureAlert> alertsToSend;
    AlertConfiguration::iterator new_rule_it;
    int rv = ac.updateRule (f, rule_name, newSubjectsToSubscribe, alertsToSend, new_rule_it);
    zmsg_t *reply = zmsg_new ();
    switch (rv) {
    case -2:
        // ERROR rule doesn't exist
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "NOT_FOUND");
        zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
            mlm_client_sender (client), RULES_SUBJECT);
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");
        zsys_debug1 ("\t--- leaving ---");
        return;
    case 0:
        // rule was updated succesfully
        zsys_debug1 ("newsubjects count = %d", newSubjectsToSubscribe.size() );
        zsys_debug1 ("alertsToSend count = %d", alertsToSend.size() );
        for ( const auto &interestedSubject : newSubjectsToSubscribe ) {
            zsys_debug1 ("Registering to receive '%s'", interestedSubject.c_str());
            mlm_client_set_consumer(client, METRICS_STREAM, interestedSubject.c_str());
            zsys_debug1("Registering finished");
        }
        // send a reply back
        zmsg_addstr (reply, "OK");
        zmsg_addstr (reply, json_representation);
        zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
            mlm_client_sender (client), RULES_SUBJECT);
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");
        // send updated alert
        zsys_debug1 ("send_alerts () start");
        send_alerts (client, alertsToSend, new_rule_it->first);
        zsys_debug1 ("send_alerts () finished");

        zsys_debug1 ("\t--- leaving ---");
        return;
    case -5:
        // error during the rule creation (lua)
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_LUA");
        zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
            mlm_client_sender (client), RULES_SUBJECT);
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");
        zsys_debug1 ("\t--- leaving ---");
        return;
    case -3:
        // rule with new rule name already exists
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "ALREADY_EXISTS");
        zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
            mlm_client_sender (client), RULES_SUBJECT);
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");
        zsys_debug1 ("\t--- leaving ---");
        return;
    case -6:
    {
        // error during the rule creation (lua)
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "Internal error - operating with storate/disk failed.");
        zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
            mlm_client_sender (client), RULES_SUBJECT);
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");
        zsys_debug1 ("\t--- leaving ---");
        return;
    }
    default:
        // error during the rule creation
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_JSON");
        zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
            mlm_client_sender (client), RULES_SUBJECT);
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");
        zsys_debug1 ("\t--- leaving ---");
        return;
    }
}


static void
change_state(
    mlm_client_t *client,
    const char *rule_name,
    const char *element_name,
    const char *new_state,
    AlertConfiguration &ac)
{
    zsys_debug1 ("\t--- entering ---");
    if ( !ac.haveRule (rule_name) )
    {
        // ERROR rule doesn't exist
        zmsg_t *reply = zmsg_new ();
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "NOT_FOUND");
        zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
            mlm_client_sender (client), ACK_SUBJECT);
        mlm_client_sendto (client, mlm_client_sender(client), ACK_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");
        zsys_debug1 ("\t--- leaving ---");
        return;
    }

    PureAlert alertToSend;
    zsys_debug1 ("updateAlertState () start");
    int rv = ac.updateAlertState (rule_name, element_name, new_state, alertToSend);
    zsys_debug1 ("updateAlertState () finished");
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
        zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
            mlm_client_sender (client), ACK_SUBJECT);
        mlm_client_sendto (client, mlm_client_sender(client), ACK_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");
        zsys_debug1 ("\t--- leaving ---");
        return;
    }
    // send a reply back
    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "OK");
    zmsg_addstr (reply, rule_name);
    zmsg_addstr (reply, element_name);
    zmsg_addstr (reply, new_state);
    zsys_debug1 ("mlm_client_sendto (address = '%s', subject = '%s), tracker != NULL, timeout = 1000",
        mlm_client_sender (client), ACK_SUBJECT);
    mlm_client_sendto (client, mlm_client_sender(client), ACK_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zsys_debug1 ("mlm_client_sendto () finished");
    // send updated alert
    zsys_debug1 ("send_alerts () start");
    send_alerts (client, {alertToSend}, rule_name);
    zsys_debug1 ("send_alerts () finished");
    zsys_debug1 ("\t--- leaving ---");
}


static void
evaluate_metric(
    mlm_client_t *client,
    const MetricInfo &triggeringMetric,
    const MetricList &knownMetricValues,
    AlertConfiguration &ac)
{
    zsys_debug1 ("\t--- entering ---");
    // Go through all known rules, and try to evaluate them
    for ( const auto &i : ac ) {
        const auto &rule = i.first;
        try {
            zsys_debug1(" # Check rule '%s'", rule->name().c_str());
            zsys_debug1 ("isTopicInteresting () start");
            bool is_interresting = rule->isTopicInteresting (triggeringMetric.generateTopic());
            zsys_debug1 ("isTopicInteresting () finished");
            
            if ( !is_interresting) {
                zsys_debug1 (" ### Metric is not interesting for this rule");
                continue;
            }

            PureAlert pureAlert;
            zsys_debug1 ("evaluate () start");
            int rv = rule->evaluate (knownMetricValues, pureAlert);
            zsys_debug1 ("evaluate () finished");
            if ( rv != 0 ) {
                zsys_error (" ### Cannot evaluate the rule '%s'", rule->name().c_str());
                continue;
            }

            PureAlert alertToSend;
            zsys_debug1 ("updateAlert () start");
            rv = ac.updateAlert (rule, pureAlert, alertToSend);
            zsys_debug1 ("updateAlert () finished");
            if ( rv == -1 ) {
                zsys_debug1 (" ### alert updated, nothing to send");
                // nothing to send
                continue;
            }
            zsys_debug1 ("send_alerts () start");
            send_alerts (client, {alertToSend}, rule);
            zsys_debug1 ("send_alerts () finished");
        }
        catch ( const std::exception &e) {
            zsys_error ("CANNOT evaluate rule, because '%s'", e.what());
        }
    }
    zsys_debug1 ("\t--- leaving ---");
}


void
bios_alert_generator_server (zsock_t *pipe, void* args)
{
    zsys_debug1 ("\t--- entering ---");
    // need to track incoming measurements
    MetricList cache;
    AlertConfiguration alertConfiguration;
    char *name = (char*) args;

    mlm_client_t *client = mlm_client_new ();

    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (client), NULL);

    zsock_signal (pipe, 0);

    while (!zsys_interrupted) {

        void *which = zpoller_wait (poller, -1);
        if (which == pipe) {
            zsys_debug1 ("which == pipe");
            zmsg_t *msg = zmsg_recv (pipe);
            char *cmd = zmsg_popstr (msg);

            if (streq (cmd, "$TERM")) {
                zsys_debug1 ("$TERM received");
                zstr_free (&cmd);
                zmsg_destroy (&msg);
                goto exit;
            }
            else
            if (streq (cmd, "VERBOSE")) {
                zsys_debug1 ("VERBOSE received");
                agent_alert_verbose = true;
                zmsg_destroy (&msg);
            }
            else
            if (streq (cmd, "CONNECT")) {
                zsys_debug1 ("CONNECT received");
                char* endpoint = zmsg_popstr (msg);
                zsys_debug1 ("mlm_client_connect (endpoint = '%s', timetou = 1000, name = '%s'",
                        endpoint, name);
                int rv = mlm_client_connect (client, endpoint, 1000, name);
                zsys_debug1 ("mlm_client_connect () finished");
                if (rv == -1)
                    zsys_error ("%s: can't connect to malamute endpoint '%s'", name, endpoint);
                zstr_free (&endpoint);
            }
            else
            if (streq (cmd, "PRODUCER")) {
                zsys_debug1 ("PRODUCER received");
                char* stream = zmsg_popstr (msg);
                zsys_debug1 ("mlm_client_set_producer (stream = '%s')", stream);
                int rv = mlm_client_set_producer (client, stream);
                zsys_debug1 ("mlm_client_set_producer () finished");
                if (rv == -1)
                    zsys_error ("%s: can't set producer on stream '%s'", name, stream);
                zstr_free (&stream);
            }
            else
            if (streq (cmd, "CONSUMER")) {
                zsys_debug1 ("CONSUMER received");
                char* stream = zmsg_popstr (msg);
                char* pattern = zmsg_popstr (msg);
                zsys_debug1 ("mlm_client_set_consumer (stream = '%s', pattern = '%s')", stream, pattern);
                int rv = mlm_client_set_consumer (client, stream, pattern);
                zsys_debug1 ("mlm_client_set_consumer () finished");
                if (rv == -1)
                    zsys_error ("%s: can't set consumer on stream '%s', '%s'", name, stream, pattern);
                zstr_free (&pattern);
                zstr_free (&stream);
            }
            else
            if (streq (cmd, "CONFIG")) {
                zsys_debug1 ("CONFIG received");
                // TODO
                char* filename = zmsg_popstr (msg);

                // Read initial configuration
                alertConfiguration.setPath(filename);
                std::set <std::string> subjectsToConsume = alertConfiguration.readConfiguration();
                zsys_debug1 ("subjectsToConsume count: %d\n", subjectsToConsume.size());

                // Subscribe to all subjects
                for ( const auto &interestedSubject : subjectsToConsume ) {
                    zsys_debug1 ("mlm_client_set_consumer (stream = '%s', pattern = '%s')",  METRICS_STREAM, interestedSubject.c_str());
                    int rv = mlm_client_set_consumer(client, METRICS_STREAM, interestedSubject.c_str());
                    zsys_debug1 ("mlm_client_set_consumer () finished");
                    if (rv == -1)
                        zsys_error ("%s: can't set consumer on stream '%s', '%s'", name, METRICS_STREAM, interestedSubject.c_str());
                        zsys_debug1("%s: Registered to receive '%s'\n", name, interestedSubject.c_str());
                }
                zstr_free (&filename);
            }
            zstr_free (&cmd);
            zmsg_destroy (&msg);
            continue;
        }
        zsys_debug1 ("which != pipe");

        // This agent is a reactive agent, it reacts only on messages
        // and doesn't do anything if there is no messages
        // TODO: probably alert also should be send every XXX seconds,
        // even if no measurements were recieved
        zsys_debug1 ("mlm_client_recv () start");
        zmsg_t *zmessage = mlm_client_recv (client);
        zsys_debug1 ("mlm_client_recv () finished");
        if ( zmessage == NULL ) {
            continue;
        }
        std::string topic = mlm_client_subject(client);
        zsys_debug1("Got message '%s'", topic.c_str());
        // There are two possible inputs and they come in different ways
        // from the stream  -> metrics
        // from the mailbox -> rules
        //                  -> request for rule list
        // but even so we try to decide according what we got, not from where
        if( is_bios_proto(zmessage) ) {
            zsys_debug1 ("bios_proto message");
            bios_proto_t *bmessage = bios_proto_decode(&zmessage);
            if( ! bmessage ) {
                zsys_debug1 ("cannot decode message, ignoring\n");
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
                    zsys_debug1 ("cannot convert value to double, ignore message\n");
                    continue;
                }
                else if (end == value || *end != '\0') {
                    zsys_debug1 ("cannot convert value to double, ignore message\n");
                    continue;
                }

                zsys_debug1("Got message '%s' with value %s\n", topic.c_str(), value);

                // Update cache with new value
                MetricInfo m (element_src, type, unit, dvalue, timestamp, "");
                bios_proto_destroy(&bmessage);
                cache.addMetric (m);
                cache.removeOldMetrics();
                zsys_debug1 ("evaluate_metric () start");
                evaluate_metric(client, m, cache, alertConfiguration);
                zsys_debug1 ("evaluate_metric () finished");
            }
            bios_proto_destroy (&bmessage);
        }
        else if ( streq (mlm_client_command (client), "MAILBOX DELIVER" ) )
        {
            zsys_debug1 ("not bios_proto && mailbox");
            // According RFC we expect here a messages
            // with the topics ACK_SUBJECT and RULE_SUBJECT
            if ( streq (mlm_client_subject (client), RULES_SUBJECT) )
            {
                zsys_debug1 ("%s", RULES_SUBJECT);
                // Here we can have:
                //  * new rule
                //  * request for list of rules
                //  * get detailed info about the rule
                char *command = zmsg_popstr (zmessage);
                char *param = zmsg_popstr (zmessage);
                if (command && param) {
                    if (streq (command, "LIST")) {
                        zsys_debug1 ("list_rules () start");
                        list_rules (client, param, alertConfiguration);
                        zsys_debug1 ("list_rules () finished");
                    }
                    else if (streq (command, "GET")) {
                        zsys_debug1 ("get_rule () start");
                        get_rule (client, param, alertConfiguration);
                        zsys_debug1 ("get_rule () finished");
                    }
                    else if (streq (command, "ADD") ) {
                        if ( zmsg_size(zmessage) == 0 ) {
                            // ADD/json
                            zsys_debug1 ("add_rule () start");
                            add_rule (client, param, alertConfiguration);
                            zsys_debug1 ("add_rule () finished");
                        }
                        else
                        {
                            // ADD/json/old_name
                            char *param1 = zmsg_popstr (zmessage);
                            zsys_debug1 ("update_rule () start");
                            update_rule (client, param, param1, alertConfiguration);
                            zsys_debug1 ("update_rule () finished");
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
                zsys_debug1 ("%s", ACK_SUBJECT);
                // Here we can have:
                //  * change acknowlegment state of the alert
                char *param1 = zmsg_popstr (zmessage); // rule name
                char *param2 = zmsg_popstr (zmessage); // element name
                char *param3 = zmsg_popstr (zmessage); // state
                if ( !param1 || !param2 || !param3 ) {
                    zsys_debug1 ("Ignore it. Unexpected message format");
                }
                else {
                    zsys_debug1 ("change_state () start");
                    change_state (client, param1, param2, param3, alertConfiguration);
                    zsys_debug1 ("change_state () finished");
                }

                zstr_free (&param1);
                zstr_free (&param2);
                zstr_free (&param3);
            }
            else
                zsys_debug1 ("Ignore it. Unexpected topic for MAILBOX message: '%s'", mlm_client_subject (client) );
        }
        zmsg_destroy (&zmessage);
    }
exit:
    zpoller_destroy (&poller);
    mlm_client_destroy (&client);
    zsys_debug1 ("\t--- leaving ---");
}

//  --------------------------------------------------------------------------
//  Self test of this class.

static char*
s_readall (const char* filename) {
    zsys_debug1 ("\t--- entering ---");
    FILE *fp = fopen(filename, "rt");
    if (!fp)
        return NULL;

    size_t fsize = 0;
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *ret = (char*) malloc (fsize * sizeof (char) + 1);
    if (!ret)
        return NULL;
    memset ((void*) ret, '\0', fsize * sizeof (char) + 1);

    size_t r = fread((void*) ret, 1, fsize, fp);
    fclose (fp);
    if (r == fsize)
        return ret;

    free (ret);
    zsys_debug1 ("\t--- leaving ---");
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

    // Test case #2.1: add new rule
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

    // Test case #2.2: add new rule with existing name
    rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    simplethreshold_rule = s_readall ("testrules/simplethreshold.rule");
    assert (simplethreshold_rule);
    zmsg_addstrf (rule, "%s", simplethreshold_rule);
    zstr_free (&simplethreshold_rule);
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

    recv = mlm_client_recv (consumer);
    assert (is_bios_proto (recv));
    brecv = bios_proto_decode (&recv);
    assert (brecv);
    assert (streq (bios_proto_rule (brecv), "simplethreshold"));
    assert (streq (bios_proto_element_src (brecv), "fff"));
    assert (streq (bios_proto_state (brecv), "ACK-PAUSE"));
    assert (streq (bios_proto_severity (brecv), "CRITICAL"));
    bios_proto_destroy (&brecv);

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

    // Test case #12: generate alert - resolved - after ACK-PAUSE
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

    // Test case #13: segfault on onbattery
    // #13.1 ADD new rule
    rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char* onbattery_rule = s_readall ("testrules/onbattery-5PX1500-01.rule");
    assert (onbattery_rule);
    zmsg_addstrf (rule, "%s", onbattery_rule);
    zstr_free (&onbattery_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);

    // #13.2 evaluate metric
    m = bios_proto_encode_metric (
            NULL, "status.ups", "5PX1500-01", "1032.000", "", -1);
    mlm_client_send (producer, "status.ups@5PX1500-01", &m);

    // Test case #14: add new rule, but with lua syntax error
    rule = zmsg_new();
    assert(rule);
    zmsg_addstrf (rule, "%s", "ADD");
    char* complexthreshold_rule_lua_error = s_readall ("testrules/complexthreshold_lua_error.rule");
    assert (complexthreshold_rule_lua_error);
    zmsg_addstrf (rule, "%s", complexthreshold_rule_lua_error);
    zstr_free (&complexthreshold_rule_lua_error);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "ERROR"));
    zstr_free (&foo);
    foo = zmsg_popstr(recv);
    assert (streq (foo, "BAD_LUA"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);

    // Test case #15.1: add Radek's testing rule
    rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char* toohigh_rule = s_readall ("testrules/too_high-ROZ.ePDU13.rule");
    assert (toohigh_rule);
    zmsg_addstrf (rule, "%s", toohigh_rule);
    zstr_free (&toohigh_rule);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    zmsg_destroy (&recv);

    // Test case #15.2: evaluate it
    m = bios_proto_encode_metric (
            NULL, "status.ups", "ROZ.UPS33", "42.00", "", -1);
    mlm_client_send (producer, "status.ups@ROZ.UPS33", &m);

    recv = mlm_client_recv (consumer);

    assert (recv);
    assert (is_bios_proto (recv));
    brecv = bios_proto_decode (&recv);
    assert (brecv);
    assert (streq (bios_proto_rule (brecv), "too_high-ROZ.ePDU13"));
    assert (streq (bios_proto_element_src (brecv), "ePDU13"));
    assert (streq (bios_proto_state (brecv), "ACTIVE"));
    assert (streq (bios_proto_severity (brecv), "CRITICAL"));
    bios_proto_destroy (&brecv);

    // Test case #15.3: evaluate it again
    m = bios_proto_encode_metric (
            NULL, "status.ups", "ROZ.UPS33", "42.00", "", -1);
    mlm_client_send (producer, "status.ups@ROZ.UPS33", &m);

    recv = mlm_client_recv (consumer);

    assert (recv);
    assert (is_bios_proto (recv));
    brecv = bios_proto_decode (&recv);
    assert (brecv);
    assert (streq (bios_proto_rule (brecv), "too_high-ROZ.ePDU13"));
    assert (streq (bios_proto_element_src (brecv), "ePDU13"));
    assert (streq (bios_proto_state (brecv), "ACTIVE"));
    assert (streq (bios_proto_severity (brecv), "CRITICAL"));
    bios_proto_destroy (&brecv);
    zmsg_destroy (&recv);

    // Test case #16.1: add new rule, with the trash at the end
    rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    char* rule_with_trash = s_readall ("testrules/rule_with_trash.rule");
    assert (rule_with_trash);
    zmsg_addstrf (rule, "%s", rule_with_trash);
    zstr_free (&rule_with_trash);
    mlm_client_sendto (ui, "alert-agent", "rfc-evaluator-rules", NULL, 1000, &rule);

    recv = mlm_client_recv (ui);

    assert (zmsg_size (recv) == 2);
    foo = zmsg_popstr (recv);
    assert (streq (foo, "OK"));
    zstr_free (&foo);
    // does not make a sense to call streq on two json documents
    zmsg_destroy (&recv);

    // Test case #16.2: add new rule, GET the rule with trash
    command = zmsg_new ();
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
    rule = zmsg_new();
    zmsg_addstrf (rule, "%s", "ADD");
    simplethreshold_rule = s_readall ("testrules/check_update_threshold_simple.rule");
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


    // no new alert sent here

    zactor_destroy (&ag_server);
    mlm_client_destroy (&ui);
    mlm_client_destroy (&consumer);
    mlm_client_destroy (&producer);
    zactor_destroy (&server);
    //  @end
    printf ("OK\n");

}
