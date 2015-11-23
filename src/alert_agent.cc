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
#include <fstream>
#include <malamute.h>
#include <bios_proto.h>
#include <math.h>

#include "rule.h"
#include "alertconfiguration.h"

//http://en.cppreference.com/w/cpp/language/typeid
//The header <typeinfo> must be included before using typeid 
#include <typeinfo>


#define THIS_AGENT_NAME "alert_agent"
#define RULES_SUBJECT "rfc-evaluator-rules"
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
        auto rules1 = ac.getRulesByType (typeid (ThresholdRuleComplex));
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
    /*
    for ( const auto &alert : alertsToSend )
    {
        // TODO
    }
    */
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
    
    // send alertsToSend
    /*
    for ( const auto &alert : alertsToSend )
    {
        // TODO
    }
    */
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
                    zsys_info(" # Check rule '%s'", rule->_rule_name.c_str());
                    if ( !rule->isTopicInteresting (m.generateTopic())) {
                        zsys_info (" ### Metric is not interesting for this rule");
                        // metric is not interesting for the rule
                        continue;
                    }

                    PureAlert *pureAlert = NULL;
                    // TODO memory leak
                    int rv = rule->evaluate (cache, &pureAlert);
                    if ( rv != 0 ) {
                        zsys_info (" ### Cannot evaluate the rule '%s'", rule->_rule_name.c_str());
                        continue;
                    }

                    auto toSend = alertConfiguration.updateAlert (rule, *pureAlert);
                    if ( toSend == NULL ) {
                        zsys_info(" ### alert updated, nothing to send");
                        // nothing to send
                        continue;
                    }
                    // TODO here add ACTIONs in the message and optional information
                    zmsg_t *alert = bios_proto_encode_alert(
                        NULL,
                        rule->_rule_name.c_str(),
                        element_src,
                        get_status_string(toSend->_status),
                        rule->_severity.c_str(),
                        toSend->_description.c_str(),
                        toSend->_timestamp,
                        NULL);
                    if( alert ) {
                        std::string atopic = rule->_rule_name + "/"
                            + rule->_severity + "@"
                            + element_src;
                        mlm_client_send(client, atopic.c_str(), &alert);
                        zmsg_destroy(&alert);
                    }
                }
                bios_proto_destroy(&bmessage);
            }
        }
        else if ( streq (mlm_client_command (client), "MAILBOX DELIVER" ) )
        {
            // TODO: According RFC we expect here a message with the topic "rfc-evaluator-rules"
            // choose better name
            if ( !streq (mlm_client_subject (client), RULES_SUBJECT) ) {
                zsys_info ("Ignore it. Unexpected topic of MAILBOX message: '%s'", mlm_client_subject (client) );
                continue;
            }
            // Here we can have:
            //  * new rule
            //  * request for list of rules
            //  * unexpected message
            // process as rule message
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
                    }
                }
            }
            if (command) free (command);
            if (param) free (param);
        }
    }
    // TODO save info to persistence before I die
    mlm_client_destroy(&client);
    return 0;
}
