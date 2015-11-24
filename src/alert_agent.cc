/*
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
*/

/*! \file alert_agent.cc
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Alert agent based on rules processing
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


#define THIS_AGENT_NAME "alert_agent"
#define RULES_SUBJECT "rfc-evaluator-rules"
#define ACK_SUBJECT "AAABBB"
#define PATH "./testrules"

// TODO TODO TODO TODO if diectory doesn't exist agent crashed
void list_rules(
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

void get_rule(
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
        zmsg_addstr (reply, "requested rule doesn't exist");
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


std::string makeActionList(
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

void send_alerts(
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
            zmsg_destroy(&msg);
        }
    }
}

void send_alerts(
    mlm_client_t *client,
    const std::vector <PureAlert> &alertsToSend,
    const Rule *rule)
{
    send_alerts (client, alertsToSend, rule->name());
}

void add_rule(
    mlm_client_t *client,
    const char *json_representation,
    AlertConfiguration &ac)
{
    std::istringstream f(json_representation);
    std::set <std::string> newSubjectsToSubscribe;
    std::vector <PureAlert> alertsToSend;
    Rule* newRule = NULL;
    int rv = ac.addRule (f, newSubjectsToSubscribe, alertsToSend, &newRule);
    if ( rv != 0 )
    {
        // ERROR during the rule creation
        zmsg_t *reply = zmsg_new ();
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "NEW_RULE_HAS_ERRORS");
        mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zmsg_destroy (&reply);
        return;

    }
    // rule was created succesfully
    zsys_info ("newsubjects count = %d", newSubjectsToSubscribe.size() );
    zsys_info ("alertsToSend count = %d", alertsToSend.size() );
    for ( const auto &interestedSubject : newSubjectsToSubscribe ) {
        mlm_client_set_consumer(client, "BIOS", interestedSubject.c_str());
        zsys_info("Registered to receive '%s'\n", interestedSubject.c_str());
    }

    // send a reply back
    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "OK");
    zmsg_addstr (reply, json_representation);
    mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
    zmsg_destroy (&reply);

    // send alertsToSend
    send_alerts (client, alertsToSend, newRule);
}


void update_rule(
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
        mlm_client_set_consumer(client, "BIOS", interestedSubject.c_str());
        zsys_info("Registered to receive '%s'\n", interestedSubject.c_str());
    }

    // send a reply back
    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "OK");
    zmsg_addstr (reply, json_representation);
    mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
    zmsg_destroy (&reply);
    send_alerts (client, alertsToSend, newRule);
}


void change_state(
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
        zmsg_addstr (reply, "RULE_NOT_FOUND");
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
        zmsg_addstr (reply, "CANT_CHANGE_ALERT_STATE");
        mlm_client_sendto (client, mlm_client_sender(client), ACK_SUBJECT, mlm_client_tracker (client), 1000, &reply);
        zmsg_destroy (&reply);
        return;
    }
    alertToSend.print ();
    // send a reply back
    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "OK");
    zmsg_addstr (reply, rule_name);
    zmsg_addstr (reply, element_name);
    zmsg_addstr (reply, new_state);
    mlm_client_sendto (client, mlm_client_sender(client), ACK_SUBJECT, mlm_client_tracker (client), 1000, &reply);
    zmsg_destroy (&reply);
    send_alerts (client, {alertToSend}, rule_name);
}


int main (int argc, char** argv)
{
    // create a malamute client
    mlm_client_t *client = mlm_client_new();
    if ( client == NULL )
    {
        zsys_error ("client cannot be created");
        return EXIT_FAILURE;
    }

    // ASSUMPTION : only one instance can be in the system
    int rv = mlm_client_connect (client, "ipc://@/malamute", 1000, THIS_AGENT_NAME);
    if ( rv == -1 )
    {
        zsys_error ("client cannot be connected");
        mlm_client_destroy(&client);
        return EXIT_FAILURE;
    }
    zsys_info ("Agent '%s' started", THIS_AGENT_NAME);
    // The goal of this agent is to produce alerts
    rv = mlm_client_set_producer (client, "ALERTS");
    if ( rv == -1 )
    {
        zsys_error ("set_producer() failed");
        mlm_client_destroy(&client);
        return EXIT_FAILURE;
    }

    // Read initial configuration
    AlertConfiguration alertConfiguration(PATH);
    std::set <std::string> subjectsToConsume = alertConfiguration.readConfiguration();
    zsys_info ("subjectsToConsume count: %d\n", subjectsToConsume.size());

    // Subscribe to all subjects
    for ( const auto &interestedSubject : subjectsToConsume ) {
        mlm_client_set_consumer(client, "BIOS", interestedSubject.c_str());
        zsys_info("Registered to receive '%s'\n", interestedSubject.c_str());
    }

    // need to track incoming measurements
    MetricList cache;

    while ( !zsys_interrupted ) {
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
            zmsg_destroy(&zmessage);
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
                cache.addMetric (m);
                cache.removeOldMetrics();

                // Go through all known rules, and try to evaluate them
                for ( const auto &rule : alertConfiguration.getRules() ) {
                    zsys_info(" # Check rule '%s'", rule->name().c_str());
                    if ( !rule->isTopicInteresting (m.generateTopic())) {
                        zsys_info (" ### Metric is not interesting for this rule");
                        // metric is not interesting for the rule
                        continue;
                    }

                    PureAlert *pureAlert = NULL;
                    // TODO memory leak
                    int rv = rule->evaluate (cache, &pureAlert);
                    if ( rv != 0 ) {
                        zsys_info (" ### Cannot evaluate the rule '%s'", rule->name().c_str());
                        continue;
                    }

                    auto toSend = alertConfiguration.updateAlert (rule, *pureAlert);
                    if ( toSend == NULL ) {
                        zsys_info(" ### alert updated, nothing to send");
                        // nothing to send
                        continue;
                    }
                    send_alerts (client, {*toSend}, rule);
                }
                bios_proto_destroy(&bmessage);
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
                if (command) free (command);
                if (param) free (param);
                continue;
            }
            if ( streq (mlm_client_subject (client), ACK_SUBJECT) )
            {
                // Here we can have:
                //  * change acknowlegment state of the alert
                char *command = zmsg_popstr (zmessage);
                char *param1 = zmsg_popstr (zmessage); // rule name
                char *param2 = zmsg_popstr (zmessage); // element name
                char *param3 = zmsg_popstr (zmessage); // state
                if ( !command || !param1 || !param2 || !param3 ) {
                    zsys_info ("Ignore it. Unexpected message format");
                    if (command) free (command);
                    if (param1) free (param1);
                    if (param2) free (param2);
                    if (param3) free (param3);
                }

                if (streq (command, "ACK")) {
                    change_state (client, param1, param2, param3, alertConfiguration);
                }
                if (command) free (command);
                if (param1) free (param1);
                if (param2) free (param2);
                if (param3) free (param3);
                continue;
            }
            zsys_info ("Ignore it. Unexpected topic for MAILBOX message: '%s'", mlm_client_subject (client) );
        }
    }
    // TODO save info to persistence before I die
    mlm_client_destroy(&client);
    return 0;
}
