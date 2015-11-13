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

#define ALERT_UNKNOWN  0
#define ALERT_START    1
#define ALERT_ACK1     2
#define ALERT_ACK2     3
#define ALERT_ACK3     4
#define ALERT_ACK4     5
#define ALERT_RESOLVED 6

const char* get_status_string(int status)
{
    switch (status) {
        case ALERT_START:
            return "ACTIVE";
        case ALERT_ACK1:
            return "ACK-WIP";
        case ALERT_ACK2:
            return "ACK-PAUSE";
        case ALERT_ACK3:
            return "ACK-IGNORE";
        case ALERT_ACK4:
            return "ACK-SILENCE";
        case ALERT_RESOLVED:
            return "RESOLVED";
    }
    return "UNKNOWN";
}


struct PureAlert{
    int status; // on Off ack
    int64_t timestamp;
    std::string description;
    std::string element;

    PureAlert(int s, int64_t tm, const std::string &descr, const std::string &element_name)
    {
        status = s;
        timestamp = tm;
        description = descr;
        element = element_name;
    };

    PureAlert()
    {
    };
};

void printPureAlert(const PureAlert &pureAlert){
    zsys_info ("status = %d", pureAlert.status);
    zsys_info ("timestamp = %d", pureAlert.timestamp);
    zsys_info ("description = %s", pureAlert.description.c_str());
    zsys_info ("element = %s", pureAlert.element.c_str());
}

// this is an abstract class for all rules
class Rule {
public:

    std::string _lua_code;
    std::string _rule_name;
    std::string _element;
    std::string _severity;
    // this field doesn't have any impact on alert evaluation
    // but this information should be propagated to GATEWAY components
    // So, need to have it here
    std::set < std::string> _actions;

    Rule(){};

    virtual int evaluate (const MetricList &metricList, PureAlert **pureAlert) const = 0;

    virtual bool isTopicInteresting(const std::string &topic) const = 0;

    virtual std::set<std::string> getNeededTopics(void) const = 0;

    bool isSameAs (const Rule &rule) const {
        if ( this->_rule_name == rule._rule_name ) {
            return true;
        }
        else {
            return false;
        }
    };

    bool isSameAs (const Rule *rule) const {
        if ( this->_rule_name == rule->_rule_name ) {
            return true;
        }
        else {
            return false;
        }
    };

    // TODO rule_name comparrission should be done in the function!
    std::string getJsonRule (void) const {
        return _json_representation;
    };

    void save (void) {
        // ASSUMPTION: file name is the same as rule name
        // rule name and file name are CASE SENSITIVE.

        std::string path = _rule_name + ".rule";
        std::ofstream ofs (path, std::ofstream::out);
        zsys_info ("here must be json: '%s'", _json_representation.c_str());
        zsys_info ("here must be file name: '%s'", path.c_str());
        ofs << _json_representation;
        ofs.close();
        return;
    };

    std::string getType(void) {
        return _type_name;
    };

protected:

    // every type of the rule should have a string representation of its name
    std::string _type_name;

    std::string _json_representation;

    // TODO rework this, as it is not required to all rules use lua for evaluation
    virtual lua_State* setContext (const MetricList &metricList) const = 0;
};


class NormalRule : public Rule
{
public:
    NormalRule(){};

    int evaluate (const MetricList &metricList, PureAlert **pureAlert) const
    {
        lua_State *lua_context = setContext (metricList);
        if ( lua_context == NULL ) {
            // not possible to evaluate metric with current known Metrics
            return 2;
        }

        zsys_info ("lua_code = %s", _lua_code.c_str() );
        int error = luaL_loadbuffer (lua_context, _lua_code.c_str(), _lua_code.length(), "line") ||
            lua_pcall (lua_context, 0, 3, 0);

        if ( error ) {
            // syntax error in evaluate
            zsys_info ("Syntax error: %s\n", lua_tostring(lua_context, -1));
            lua_close (lua_context);
            return 1;
        }
        // if we are going to use the same context repeatedly -> use lua_pop(lua_context, 1)
        // to pop error message from the stack

        // evaluation was successful, need to read the result
        if ( !lua_isstring (lua_context, -1) ) {
            zsys_info ("unexcpected returned value\n");
            lua_close (lua_context);
            return -1;
        }
        // ok, in the lua stack we got, what we expected
        const char *status_ = lua_tostring(lua_context, -1); // IS / ISNT
        zsys_info ("status = %s", status_ );
        int s = ALERT_UNKNOWN;
        if ( strcmp (status_, "IS") == 0 ) {
            s = ALERT_START;
        }
        else if ( strcmp (status_, "ISNT") == 0 ) {
            s = ALERT_RESOLVED;
        }
        if ( s == ALERT_UNKNOWN ) {
            zsys_info ("unexcpected returned value, expected IS/ISNT\n");
            lua_close (lua_context);
            return -5;
        }
        if ( !lua_isstring(lua_context, -3) ) {
            zsys_info ("unexcpected returned value\n");
            lua_close (lua_context);
            return -3;
        }
        const char *description = lua_tostring(lua_context, -3);
        *pureAlert = new PureAlert(s, ::time(NULL), description, _element);
        printPureAlert (**pureAlert);
        lua_close (lua_context);
        return 0;
    };

    bool isTopicInteresting(const std::string &topic) const
    {
        return ( _in.count(topic) != 0 ? true : false );
    };

    std::set<std::string> getNeededTopics(void) const {
        return _in;
    };

    friend Rule* readRule (std::istream &f);

protected:

    lua_State* setContext (const MetricList &metricList) const
    {
        lua_State *lua_context = lua_open();
        for ( const auto &neededTopic : _in)
        {
            double neededValue = metricList.find (neededTopic);
            if ( isnan (neededValue) ) {
                zsys_info("Do not have everything for '%s' yet\n", _rule_name.c_str());
                lua_close (lua_context);
                return NULL;
            }
            std::string var = neededTopic;
            var[var.find('@')] = '_';
            zsys_info("Setting variable '%s' to %lf\n", var.c_str(), neededValue);
            lua_pushnumber (lua_context, neededValue);
            lua_setglobal (lua_context, var.c_str());
        }
        // we are here -> all variables were found
        return lua_context;
    };

private:

    std::set<std::string> _in;

};


class ThresholdRule : public Rule
{
    // TODO Why do we need to generate lua? We can easily do it in c++ !!!
public:
    ThresholdRule(){};

    int evaluate (const MetricList &metricList, PureAlert **pureAlert) const
    {
        lua_State *lua_context = setContext (metricList);
        if ( lua_context == NULL ) {
            // not possible to evaluate metric with current known Metrics
            return 2;
        }

        zsys_info ("lua_code = %s", _lua_code.c_str() );
        int error = luaL_loadbuffer (lua_context, _lua_code.c_str(), _lua_code.length(), "line") ||
            lua_pcall (lua_context, 0, 3, 0);

        if ( error ) {
            // syntax error in evaluate
            zsys_info ("Syntax error: %s\n", lua_tostring(lua_context, -1));
            lua_close (lua_context);
            return 1;
        }
        // if we are going to use the same context repeatedly -> use lua_pop(lua_context, 1)
        // to pop error message from the stack

        // evaluation was successful, need to read the result
        if ( !lua_isstring (lua_context, -1) ) {
            zsys_info ("unexcpected returned value\n");
            lua_close (lua_context);
            return -1;
        }
        // ok, in the lua stack we got, what we expected
        const char *status_ = lua_tostring(lua_context, -1); // IS / ISNT
        zsys_info ("status = %s", status_ );
        int s = ALERT_UNKNOWN;
        if ( strcmp (status_, "IS") == 0 ) {
            s = ALERT_START;
        }
        else if ( strcmp (status_, "ISNT") == 0 ) {
            s = ALERT_RESOLVED;
        }
        if ( s == ALERT_UNKNOWN ) {
            zsys_info ("unexcpected returned value, expected IS/ISNT\n");
            lua_close (lua_context);
            return -5;
        }
        if ( !lua_isstring(lua_context, -3) ) {
            zsys_info ("unexcpected returned value\n");
            lua_close (lua_context);
            return -3;
        }
        const char *description = lua_tostring(lua_context, -3);
        *pureAlert = new PureAlert(s, ::time(NULL), description, _element);
        printPureAlert (**pureAlert);
        lua_close (lua_context);
        return 0;
    };

    bool isTopicInteresting(const std::string &topic) const
    {
        return ( _in == topic ? true : false );
    };

    std::set<std::string> getNeededTopics(void) const {
        return {_in};
    };

    friend Rule* readRule (std::istream &f);

protected:

    void generateLua (void)
    {
        // assumption: at this point type can have only two values
        if ( _type == "low" )
        {
            _lua_code = "if ( ";
            _lua_code += _metric;
            _lua_code += "_";
            _lua_code += _element;
            _lua_code += " <  ";
            _lua_code += std::to_string(_value);
            _lua_code += " ) then return \"Element ";
            _lua_code += _element;
            _lua_code += " is lower than threshold";
            _lua_code += "\", ";
            _lua_code += std::to_string(_value);
            _lua_code += ", \"IS\" else return \"\", ";
            _lua_code += std::to_string(_value);
            _lua_code += " , \"ISNT\" end";
        }
        else
        {
            _lua_code = "if ( ";
            _lua_code += _metric;
            _lua_code += "_";
            _lua_code += _element;
            _lua_code += " >  ";
            _lua_code += std::to_string(_value);
            _lua_code += " ) then return \"Element ";
            _lua_code += _element;
            _lua_code += " is higher than threshold";
            _lua_code += "\", ";
            _lua_code += std::to_string(_value);
            _lua_code += ", \"IS\" else return \"\", ";
            _lua_code += std::to_string(_value);
            _lua_code += " , \"ISNT\" end";
        }
        zsys_info ("generated_lua = %s", _lua_code.c_str());
    };

    void generateNeededTopic (void)
    {
        // it is bad to open the notion, how topic is formed, but for now there is now better place
        _in = _metric + "@" + _element;
    };

    lua_State* setContext (const MetricList &metricList) const
    {
        lua_State *lua_context = lua_open();
        double neededValue = metricList.find (_in);
        if ( isnan (neededValue) ) {
            zsys_info("Do not have everything for '%s' yet\n", _rule_name.c_str());
            lua_close (lua_context);
            return NULL;
        }
        std::string var = _metric + "_" + _element;
        zsys_info("Setting variable '%s' to %lf\n", var.c_str(), neededValue);
        lua_pushnumber (lua_context, neededValue);
        lua_setglobal (lua_context, var.c_str());
        return lua_context;
    };

private:
    std::string _metric;
    std::string _type;
    double _value;
    // this field is generated field
    std::string _in;
};

class RegexRule : public Rule {
public:

    RegexRule()
    {
        _rex = NULL;
    };

    int evaluate (const MetricList &metricList, PureAlert **pureAlert) const
    {
        lua_State *lua_context = setContext (metricList);
        if ( lua_context == NULL ) {
            // not possible to evaluate metric with current known Metrics
            return 2;
        }

        zsys_info ("lua_code = %s", _lua_code.c_str() );
        int error = luaL_loadbuffer (lua_context, _lua_code.c_str(), _lua_code.length(), "line") ||
            lua_pcall (lua_context, 0, 4, 0);

        if ( error ) {
            // syntax error in evaluate
            zsys_info ("Syntax error: %s\n", lua_tostring(lua_context, -1));
            lua_close (lua_context);
            return 1;
        }
        // if we are going to use the same context repeatedly -> use lua_pop(lua_context, 1)
        // to pop error message from the stack

        // evaluation was successful, need to read the result
        if ( !lua_isstring (lua_context, -1) ) {
            zsys_info ("unexcpected returned value\n");
            lua_close (lua_context);
            return -1;
        }
        // ok, in the lua stack we got, what we expected
        const char *status_ = lua_tostring(lua_context, -1); // IS / ISNT
        zsys_info ("status = %s", status_ );
        int s = ALERT_UNKNOWN;
        if ( strcmp (status_, "IS") == 0 ) {
            s = ALERT_START;
        }
        else if ( strcmp (status_, "ISNT") == 0 ) {
            s = ALERT_RESOLVED;
        }
        if ( s == ALERT_UNKNOWN ) {
            zsys_info ("unexcpected returned value, expected IS/ISNT\n");
            lua_close (lua_context);
            return -5;
        }
        if ( !lua_isstring(lua_context, -3) ) {
            zsys_info ("unexcpected returned value\n");
            lua_close (lua_context);
            return -3;
        }
        if ( !lua_isstring(lua_context, -4) ) {
            zsys_info ("unexcpected returned value\n");
            lua_close (lua_context);
            return -4;
        }
        const char *description = lua_tostring(lua_context, -3);
        const char *element_a = lua_tostring(lua_context, -4);
        *pureAlert = new PureAlert(s, ::time(NULL), description, element_a);
        printPureAlert (**pureAlert);
        lua_close (lua_context);
        return 0;
    };

    bool isTopicInteresting(const std::string &topic) const
    {
        return zrex_matches (_rex, topic.c_str());
    };

    std::set<std::string> getNeededTopics(void) const
    {
        return std::set<std::string>{_rex_str};
    };

    friend Rule* readRule (std::istream &f);

protected:

    lua_State* setContext (const MetricList &metricList) const
    {
        MetricInfo metricInfo = metricList.getLastMetric();
        lua_State *lua_context = lua_open();
        lua_pushnumber(lua_context, metricInfo.getValue());
        lua_setglobal(lua_context, "value");
        zsys_info("Setting value to %lf\n", metricInfo.getValue());
        lua_pushstring(lua_context, metricInfo.getElementName().c_str());
        lua_setglobal(lua_context, "element");
        zsys_info("Setting element to %s\n", metricInfo.getElementName().c_str());
        return lua_context;
    };

private:
    zrex_t *_rex;
    std::string _rex_str;
};

// It tries to simply parse and read JSON
Rule* readRule (std::istream &f)
{
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

class AlertConfiguration{
public:
    AlertConfiguration (const std::string &path)
        : _path (path)
    {};

    ~AlertConfiguration(){};

    // returns list of topics to be consumed
    std::set <std::string> readConfiguration(void)
    {
        std::set <std::string> result;

        cxxtools::Directory d(_path);
        std::vector<PureAlert> emptyAlerts{};
        for ( const auto &fn : d)
        {
            if ( fn.length() < 5 ) {
                continue;
            }
            if ( fn.compare(fn.length() - 5, 5, ".rule") != 0 ) {
                continue;
            }
            zsys_info ("json to parse: %s", fn.c_str());
            // TODO check, that rule_name and file have the same names
            std::ifstream f(fn);
            // TODO memory leak
            Rule *rule = readRule (f);
            if ( rule == NULL ) {
                zsys_info ("nothing to do");
                continue;
            }
            // TODO check, that rule name is unique
            // TODO check, that rule actions are value
            for ( const auto &interestedTopic : rule->getNeededTopics() ) {
                result.insert (interestedTopic);
            }
            _alerts.push_back (std::make_pair(rule, emptyAlerts));
            _configs.push_back (rule);
        }
        return result;
    };

    std::vector<Rule*> getRules(void)
    {
        return _configs;
    };

    // alertsToSend must be send in the order from first element to last element!!!
    int updateConfiguration(std::istream &newRuleString, std::set <std::string> &newSubjectsToSubscribe, std::vector <PureAlert> &alertsToSend, Rule** newRule)
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
                if ( ! oneRuleAlerts.first->isSameAs (*newRule) ) {
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
                    if ( oneRule->isSameAs (*newRule) ) {
                        // -- free memory used by oldone
                        delete oneRule;
                        oneRule = *newRule;
                    }
                }
                // -- use new rule
                oneRuleAlerts.first = *newRule;
            }

            // TODO delete old rule from persistance
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
            if ( !oneRuleAlerts.first->isSameAs (rule) ) {
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
        for ( const auto &oneRule: _configs ) {
            if ( oneRule->isSameAs(rule) )
                return true;
        }
        return false;
    };

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

int main (int argc, char** argv)
{
    // create a malamute client
    mlm_client_t *client = mlm_client_new();
    // ASSUMPTION : only one instance can be in the system
    mlm_client_connect (client, "ipc://@/malamute", 1000, THIS_AGENT_NAME);
    zsys_info ("Agent '%s' started", THIS_AGENT_NAME);
    // The goal of this agent is to produce alerts
    mlm_client_set_producer (client, "ALERTS");

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

                std::string topic = mlm_client_subject(client);
                zsys_info("Got message '%s' with value %s\n", topic.c_str(), value);

                // Update cache with new value
                MetricInfo m (element_src, type, unit, dvalue, timestamp, "");
                cache.addMetric (m);
                cache.removeOldMetrics();

                for ( const auto &rule : alertConfiguration.getRules() ) {
                    if ( !rule->isTopicInteresting (m.generateTopic())) {
                        // metric is not interesting for the rule
                        continue;
                    }

                    PureAlert *pureAlert = NULL;
                    // TODO memory leak
                    // TODO return value
                    rule->evaluate (cache, &pureAlert);
                    if ( pureAlert == NULL ) {
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
    // TODO save info to persistence before I die
    mlm_client_destroy(&client);
    return 0;
}
