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

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

#include <string.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <map>
#include <iostream>
#include <fstream>
#include <cxxtools/jsondeserializer.h>
#include <cxxtools/jsonserializer.h>
#include <cxxtools/directory.h>
#include <malamute.h>
#include <bios_proto.h>
#include <math.h>

#include "metriclist.h"
#include "normalrule.h"
#include "thresholdrulesimple.h"
#include "thresholdrule.h"
#include "regexrule.h"


// It tries to simply parse and read JSON
Rule* readRule (std::istream &f)
{
    // TODO check, that rule actions are value
    try {
        std::string json_string(std::istreambuf_iterator<char>(f), {});
        std::stringstream s(json_string);
        cxxtools::JsonDeserializer json(s);
        json.deserialize();
        const cxxtools::SerializationInfo *si = json.si();
        // TODO too complex method, need to split it
        if ( si->findMember("in") ) {
            NormalRule *rule = new NormalRule();
            try {
                si->getMember("in") >>= rule->_in;
                si->getMember("element") >>= rule->_element;
                si->getMember("evaluation") >>= rule->_lua_code;
                si->getMember("rule_name") >>= rule->_rule_name;
                si->getMember("severity") >>= rule->_severity;
                rule->_json_representation = json_string;
            }
            catch ( const std::exception &e ) {
                zsys_warning ("NORMAL rule doesn't have all required fields, ignore it. %s", e.what());
                delete rule;
                return NULL;
            }
            // this field is optional
            if ( si->findMember("action") ) {
                si->getMember("action") >>= rule->_actions;
            }
            zsys_info ("lua = %s", rule->_lua_code.c_str());
            return rule;
        }
        else if ( si->findMember("in_rex") ) {
            RegexRule *rule = new RegexRule();
            try {
                si->getMember("in_rex") >>= rule->_rex_str;
                rule->_rex = zrex_new(rule->_rex_str.c_str());
                si->getMember("evaluation") >>= rule->_lua_code;
                si->getMember("rule_name") >>= rule->_rule_name;
                si->getMember("severity") >>= rule->_severity;
                zsys_info ("lua = %s", rule->_lua_code.c_str());
                rule->_json_representation = json_string;
            }
            catch ( const std::exception &e ) {
                zsys_warning ("REGEX rule doesn't have all required fields, ignore it. %s", e.what());
                delete rule;
                return NULL;
            }
            // this field is optional
            if ( si->findMember("action") ) {
                si->getMember("action") >>= rule->_actions;
            }
            return rule;
        } else if ( si->findMember("metric") ){
            ThresholdRule *rule = new ThresholdRule();
            try {
                si->getMember("metric") >>= rule->_metric;
                si->getMember("element") >>= rule->_element;
                si->getMember("rule_name") >>= rule->_rule_name;
                si->getMember("severity") >>= rule->_severity;
                si->getMember("type") >>= rule->_type;
                si->getMember("value") >>= rule->_value;
                rule->_json_representation = json_string;
            }
            catch ( const std::exception &e ) {
                zsys_warning ("THRESHOLD rule doesn't have all required fields, ignore it. %s", e.what());
                delete rule;
                return NULL;
            }
            // this field is optional
            if ( si->findMember("action") ) {
                si->getMember("action") >>= rule->_actions;
            }
            rule->generateLua();
            rule->generateNeededTopic();
            return rule;
        } else if ( si->findMember("threshold") != NULL ){
            Rule *rule;
            try {
                auto threshold = si->getMember("threshold");
                if ( threshold.category () != cxxtools::SerializationInfo::Object ) {
                    zsys_info ("Root of json must be an object with property 'threshold'.");
                    // TODO
                    return NULL;
                }

                try {
                    // metric
                    auto metric = threshold.getMember("metric");
                    if ( metric.category () == cxxtools::SerializationInfo::Value ) {
                        ThresholdRuleSimple *tmp_rule = new ThresholdRuleSimple();
                        metric >>= tmp_rule->_metric;
                        rule = tmp_rule;
                    }
                    else if ( metric.category () == cxxtools::SerializationInfo::Array ) {
                        rule = new RegexRule;
                        // TODO change to complex rule
                    }
                }
                catch ( const std::exception &e) {
                    // TODO
                    return NULL;
                }
                threshold.getMember("rule_name") >>= rule->_rule_name;
                threshold.getMember("element") >>= rule->_element;
                // values
                // TODO check low_critical < low_warnong < high_warning < hign crtical
                auto values = threshold.getMember("values");
                if ( values.category () != cxxtools::SerializationInfo::Array ) {
                    zsys_info ("parameter 'values' in json must be an array.");
                    // TODO
                    throw "eee";
                }
                values >>= rule->_values;
                // outcomes
                auto outcomes = threshold.getMember("results");
                if ( outcomes.category () != cxxtools::SerializationInfo::Array ) {
                    zsys_info ("parameter 'results' in json must be an array.");
                    // TODO
                    throw "eee";
                }
                outcomes >>= rule->_outcomes;

/*
{
    "threshold" : {
        "rule_name"     :   "<rule_name>",
        "element"       :   "<element_name>",
        "values"        :   [ "low_critical"  : "<value>",
                              "low_warning"   : "<value>",
                              "high_warning"  : "<value>",
                              "high_critical" : "<value>"
                            ],
        "results"       :   [ "low_critical"  : { "action" : ["<action_1>", ..., "<action_N>"], "severity" : "<severity>", "description" : "<description>" },
                              "low_warning"   : { "action" : ["<action_1>", ..., "<action_N>"], "severity" : "<severity>", "description" : "<description>" },
                              "high_warning"  : { "action" : ["<action_1>", ..., "<action_N>"], "severity" : "<severity>", "description" : "<description>" },
                              "high_critical" : { "action" : ["<action_1>", ..., "<action_N>"], "severity" : "<severity>", "description" : "<description>" }
                            ],
        "metric"        :   <metric_specification>,
        "evaluation"    :   "<lua_function>"
    }
}
*/


                rule->_json_representation = json_string;
            }
            catch ( const std::exception &e ) {
                zsys_warning ("THRESHOLD rule doesn't have all required fields, ignore it. %s", e.what());
                delete rule;
                return NULL;
            }
            return rule;
        }
        else {
            zsys_warning ("Cannot detect type of the rule, ignore it");
            return NULL;
        }
    }
    catch ( const std::exception &e) {
        zsys_error ("Cannot parse JSON, ignore it");
        return NULL;
    }
};

// Alert configuration is class that manage rules and evaruted alerts
//
// ASSUMPTIONS:
//  1. Rules are stored in files. One rule = one file
//  2. File name is a rule name
//  3. Files should have extention ".rule
//  4. Directory to the files is configurable. Cannot be changed without recompilation
//  5. If rule has at least one mostake or broke any rule, it is ignored
//  6. Rule name is unique string
//
//
class AlertConfiguration{
public:

    /*
     * \brief Creates an enpty rule-alert configuration
     *
     * \param[in] @path - a directory where rules are stored
     */
    AlertConfiguration (const std::string &path)
        : _path (path)
    {};

    /*
     * \brief Destroys alert configuration
     */
    ~AlertConfiguration() {
        for ( auto &oneRule : _configs )
            delete oneRule;
    };

    // returns list of topics to be consumed
    // Reads rules from persistence
    std::set <std::string> readConfiguration (void)
    {
        // list of topics, that are needed to be consumed for rules
        std::set <std::string> result;

        cxxtools::Directory d(_path);
        // every rule at the beggining has empty set of alerts
        std::vector<PureAlert> emptyAlerts{};
        for ( const auto &fn : d)
        {
            // we are interested only in files with names "*.rule"
            if ( fn.length() < 5 ) {
                continue;
            }
            if ( fn.compare(fn.length() - 5, 5, ".rule") != 0 ) {
                continue;
            }

            // read rule from the file
            std::ifstream f(fn);
            Rule *rule = readRule (f);
            if ( rule == NULL ) {
                // rule can't be read correctly from the file
                zsys_info ("nothing to do");
                continue;
            }

            // ASSUMPTION: name of the file is the same as name of the rule
            // If they are different ignore this rule
            if ( !rule->hasSameNameAs (fn) ) {
                zsys_info ("file name '%s' differs from rule name '%s', ignore it", fn.c_str(), rule->_rule_name.c_str());
                delete rule;
                continue;
            }

            // ASSUMPTION: rules have unique names
            if ( haveRule (rule) ) {
                zsys_info ("rule with name '%s' already known, ignore this one. File '%s'", rule->_rule_name.c_str(), fn.c_str());
                delete rule;
                continue;
            }

            // record topics we are interested in
            for ( const auto &interestedTopic : rule->getNeededTopics() ) {
                result.insert (interestedTopic);
            }
            // add rule to the configuration
            _alerts.push_back (std::make_pair(rule, emptyAlerts));
            _configs.push_back (rule);
            zsys_info ("file '%s' readed correctly", fn.c_str());
        }
        return result;
    };

    std::vector<Rule*> getRules (void)
    {
        return _configs;
    };

    // alertsToSend must be send in the order from first element to last element!!!
    int updateConfiguration (
        std::istream &newRuleString,
        std::set <std::string> &newSubjectsToSubscribe,
        std::vector <PureAlert> &alertsToSend,
        Rule** newRule)
    {
        // ASSUMPTION: function should be used as intended to be used
        assert (newRule);
        // ASSUMPTIONS: newSubjectsToSubscribe and  alertsToSend are empty
        // TODO memory leak
        *newRule = readRule (newRuleString);
        if ( *newRule == NULL ) {
            zsys_info ("nothing to update");
            return -1;
        }
        // need to find out if rule exists already or not
        if ( !haveRule (*newRule) )
        {
            // add new rule
            std::vector<PureAlert> emptyAlerts{};
            _alerts.push_back (std::make_pair(*newRule, emptyAlerts));
            _configs.push_back (*newRule);
        }
        else
        {
            // find alerts, that should be resolved
            for ( auto &oneRuleAlerts: _alerts ) {
                if ( ! oneRuleAlerts.first->hasSameNameAs (*newRule) ) {
                    continue;
                }
                // so we finally found a list of alerts
                // resolve found alerts
                for ( auto &oneAlert : oneRuleAlerts.second ) {
                    oneAlert.status = ALERT_RESOLVED;
                    oneAlert.description = "Rule changed";
                    // put them into the list of alerts that changed
                    alertsToSend.push_back (oneAlert);
                }
                oneRuleAlerts.second.clear();
                // update rule
                // This part is ugly, as there are duplicate pointers
                for ( auto &oneRule: _configs ) {
                    if ( oneRule->hasSameNameAs (*newRule) ) {
                        // -- free memory used by oldone
                        delete oneRule;
                        oneRule = *newRule;
                    }
                }
                // -- use new rule
                oneRuleAlerts.first = *newRule;
            }
        }
        // in any case we need to check new subjects
        for ( const auto &interestedTopic : (*newRule)->getNeededTopics() ) {
            newSubjectsToSubscribe.insert (interestedTopic);
        }
        (*newRule)->save();
        // CURRENT: wait until new measurements arrive
        // TODO: reevaluate immidiately ( new Method )
        // reevaluate rule for every known metric
        //  ( requires more sophisticated approach: need to refactor evaluate back for 2 params + some logic here )
        return 0;
    };

    PureAlert* updateAlert (const Rule *rule, const PureAlert &pureAlert)
    {
        for ( auto &oneRuleAlerts : _alerts ) // this object can be changed -> no const
        {
            if ( !oneRuleAlerts.first->hasSameNameAs (rule) ) {
                continue;
            }
            // we found the rule
            bool isAlertFound = false;
            for ( auto &oneAlert : oneRuleAlerts.second ) // this object can be changed -> no const
            {
                bool isSameAlert = ( pureAlert.element == oneAlert.element );
                if ( !isSameAlert ) {
                    continue;
                }
                // we found the alert
                isAlertFound = true;
                if ( pureAlert.status == ALERT_START ) {
                    if ( oneAlert.status == ALERT_RESOLVED ) {
                        // Found alert is old. This is new one
                        oneAlert.status = pureAlert.status;
                        oneAlert.timestamp = pureAlert.timestamp;
                        oneAlert.description = pureAlert.description;
                        // element is the same -> no need to update the field
                        zsys_info("RULE '%s' : OLD ALERT starts again for element '%s' with description '%s'\n", oneRuleAlerts.first->_rule_name.c_str(), oneAlert.element.c_str(), oneAlert.description.c_str());
                    }
                    else {
                        // Found alert is still active -> it is the same alert
                        zsys_info("RULE '%s' : ALERT is ALREADY ongoing for element '%s' with description '%s'\n", oneRuleAlerts.first->_rule_name.c_str(), oneAlert.element.c_str(), oneAlert.description.c_str());
                    }
                    // in both cases we need to send an alert
                    PureAlert *toSend = new PureAlert(oneAlert);
                    return toSend;
                }
                if ( pureAlert.status == ALERT_RESOLVED ) {
                    if ( oneAlert.status != ALERT_RESOLVED ) {
                        // Found alert is not resolved. -> resolve it
                        oneAlert.status = pureAlert.status;
                        oneAlert.timestamp = pureAlert.timestamp;
                        oneAlert.description = pureAlert.description;
                        zsys_info("RULE '%s' : ALERT is resolved for element '%s' with description '%s'\n", oneRuleAlerts.first->_rule_name.c_str(), oneAlert.element.c_str(), oneAlert.description.c_str());
                        PureAlert *toSend = new PureAlert(oneAlert);
                        return toSend;
                    }
                    else {
                        // alert was already resolved -> nothing to do
                        return NULL;
                    }
                }
            } // end of proceesing existing alerts
            if ( !isAlertFound )
            {
                // this is completly new alert -> need to add it to the list
                // but  only if alert is not resolved
                if ( pureAlert.status != ALERT_RESOLVED )
                {
                    oneRuleAlerts.second.push_back(pureAlert);
                    zsys_info("RULE '%s' : ALERT is NEW for element '%s' with description '%s'\n", oneRuleAlerts.first->_rule_name.c_str(), pureAlert.element.c_str(), pureAlert.description.c_str());
                    PureAlert *toSend = new PureAlert(pureAlert);
                    return toSend;
                }
                else
                {
                    // nothing to do, no need to add to the list resolved alerts
                }
            }
        } // end of processing one rule
    };

    bool haveRule (const Rule *rule) const {
        for ( const auto &oneKnownRule: _configs ) {
            if ( rule->hasSameNameAs(oneKnownRule) )
                return true;
        }
        return false;
    };

    /**
     * \brief get list of rules by type
     * \return vector of Rule*
     *
     * Use getRulesByType( typeid(ThresholdRule) ) for getting all thresholds.
     * Use getRulesByType( typeid(Rule) ) for getting all rules.
     */
    std::vector<Rule*> getRulesByType ( const std::type_info &type_id ) {
        ThresholdRule T; // need this for getting mangled class name
        std::vector<Rule *> result;
        for (auto rule : _configs) {
            zsys_info("T type %s", typeid(rule).name() );
            if( type_id == typeid(Rule) || type_id == typeid(rule) ) {
                result.push_back(rule);
            }
        }
        return result;
    }

    Rule* getRuleByName ( const std::string &name ) {
        // TODO: make some map of names to avoid o(n)?
        // Return iterator rather than pointer?
        for (auto rule : _configs) {
            if( rule->hasSameNameAs( name ) ) return rule;
        }
        return NULL;
    }

private:
    // TODO it is bad implementation, any improvements are welcome
    std::vector <std::pair<Rule*, std::vector<PureAlert> > > _alerts;

    std::vector <Rule*> _configs;

    // directory, where rules are stored
    std::string _path;
};


// mockup
int  rule_decode (zmsg_t **msg, std::string &rule_json)
{
    rule_json = "{\"rule_name\": \"threshold1_from_mailbox\",\"severity\": \"CRITICAL\", "
        "  \"metric\" : \"humidity\","
        "  \"type\" : \"low\","
        "  \"element\": \"CCC\","
        "  \"value\": 5.666,"
        "  \"action\" : [\"EMAIL\", \"SMS\"]}";
    zmsg_destroy (msg);
    return 0;
};

#define THIS_AGENT_NAME "alert_generator"
#define PATH "."

void list_rules(mlm_client_t *client, const char *type, AlertConfiguration &ac) {
    std::vector<Rule*> rules;

    if (streq (type,"all")) {
        rules = ac.getRulesByType ( typeid(Rule) );
    }
    else if (streq (type,"threshold")) {
        rules = ac.getRulesByType (typeid (ThresholdRule));
    }
    else if (streq (type,"single")) {
        rules = ac.getRulesByType (typeid (NormalRule));
    }
    else if (streq (type,"pattern")) {
        rules = ac.getRulesByType (typeid (RegexRule));
    }
    else {
        //invalid type, TODO send message
        zmsg_t *reply = zmsg_new ();
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "requested set of rules is invalid");
        mlm_client_sendto (client, mlm_client_sender(client), "rfc-thresholds", mlm_client_tracker (client), 1000, &reply);
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
    mlm_client_sendto (client, mlm_client_sender(client), "rfc-thresholds", mlm_client_tracker(client), 1000, &reply);
    zmsg_destroy( &reply );
}

void get_rule(mlm_client_t *client, const char *name, AlertConfiguration &ac) {
    Rule *rule = ac.getRuleByName(name);
    if(!rule) {
        //invalid type, TODO send message
        zmsg_t *reply = zmsg_new ();
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "requested rule doesn't exist");
        mlm_client_sendto (client, mlm_client_sender(client), "rfc-thresholds", mlm_client_tracker (client), 1000, &reply);
        zmsg_destroy (&reply);
        return;
    }
    zmsg_t *reply = zmsg_new ();
    assert (reply);
    zmsg_addstr (reply, "OK");
    zmsg_addstr (reply, rule->getJsonRule().c_str());
    mlm_client_sendto (client, mlm_client_sender(client), "rfc-thresholds", mlm_client_tracker(client), 1000, &reply);
    zmsg_destroy( &reply );
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
                    if ( !rule->isTopicInteresting (m.generateTopic())) {
                        // metric is not interesting for the rule
                        continue;
                    }

                    PureAlert *pureAlert = NULL;
                    // TODO memory leak
                    int rv = rule->evaluate (cache, &pureAlert);
                    if ( rv != 0 ) {
                        zsys_info ("cannot evaluate the rule '%s'", rule->_rule_name.c_str());
                        continue;
                    }

                    auto toSend = alertConfiguration.updateAlert (rule, *pureAlert);
                    if ( toSend == NULL ) {
                        // nothing to send
                        continue;
                    }
                    // TODO here add ACTIONs in the message and optional information
                    zmsg_t *alert = bios_proto_encode_alert(
                        NULL,
                        rule->_rule_name.c_str(),
                        element_src,
                        get_status_string(toSend->status),
                        rule->_severity.c_str(),
                        toSend->description.c_str(),
                        toSend->timestamp,
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
            // According RFC we expect here a message with the topic "rfc-thresholds"
            if ( !streq (mlm_client_subject (client), "rfc-thresholds") ) {
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
                    std::string rule_json;
                    int rv = rule_decode (&zmessage, rule_json);
                    zsys_info ("new_json: %s", rule_json.c_str());
                    if ( rv != 0 ) {
                        zsys_info ("cannot decode rule information, ignore message\n");
                        continue;
                    }
                    std::string topic = mlm_client_subject(client);
                    zsys_info("Got message '%s'", topic.c_str());
                    // TODO memory leak

                    std::istringstream f(rule_json);
                    std::set <std::string> newSubjectsToSubscribe;
                    std::vector <PureAlert> alertsToSend;
                    Rule* newRule = NULL;
                    rv = alertConfiguration.updateConfiguration (f, newSubjectsToSubscribe, alertsToSend, &newRule);
                    zsys_info ("rv = %d", rv);
                    zsys_info ("newsubjects count = %d", newSubjectsToSubscribe.size() );
                    zsys_info ("alertsToSend count = %d", alertsToSend.size() );
                    for ( const auto &interestedSubject : newSubjectsToSubscribe ) {
                        mlm_client_set_consumer(client, "BIOS", interestedSubject.c_str());
                        zsys_info("Registered to receive '%s'\n", interestedSubject.c_str());
                    }
                    // TODO send a reply back
                    // TODO send alertsToSend
                    
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
