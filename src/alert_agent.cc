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
#include <cxxtools/directory.h>
#include <malamute.h>
#include "bios_proto.h"
#include <math.h>

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

class MetricInfo {
public:
    std::string _element_name;
    std::string _source;
    std::string _units;
    double      _value;
    int64_t     _timestamp;
    std::string _element_destination_name;

    std::string generateTopic(void) const{
        return _source + "@" + _element_name;
    };

    MetricInfo() {};
    MetricInfo (
        const std::string &element_name,
        const std::string &source,
        const std::string &units,
        double value,
        int64_t timestamp,
        const std::string &destination
        ):
        _element_name(element_name),
        _source(source),
        _units(units),
        _value(value),
        _timestamp(timestamp),
        _element_destination_name (destination)
    {};

    void print(void)
    {
        zsys_info ("element_name = %s", _element_name.c_str());
        zsys_info ("source = %s", _source.c_str());
        zsys_info ("units = %s", _units.c_str());
        zsys_info ("value = %lf", _value);
        zsys_info ("timestamp = %d", _timestamp);
        zsys_info ("destination = %s", _element_destination_name.c_str());
    };
};


class MetricList {
public:
    MetricList(){};
    ~MetricList(){};

    void addMetric (
        const std::string &element_name,
        const std::string &source,
        const std::string &units,
        double value,
        int64_t timestamp,
        const std::string &destination)
    {
        // create Metric first
        MetricInfo m = MetricInfo(element_name,
                                  source,
                                  units,
                                  value,
                                  timestamp,
                                  destination);

        // try to find topic
        auto it = knownMetrics.find (m.generateTopic());
        if ( it != knownMetrics.cend() ) {
            // if it was found -> replace with new value
            it->second = m;
        }
        else {
            // if it wasn't found -> insert new metric
            knownMetrics.emplace (m.generateTopic(), m);
        }
    };

    void addMetric (const MetricInfo &m)
    {
        // try to find topic
        auto it = knownMetrics.find (m.generateTopic());
        if ( it != knownMetrics.cend() ) {
            // if it was found -> replace with new value
            it->second = m;
        }
        else {
            // if it wasn't found -> insert new metric
            knownMetrics.emplace (m.generateTopic(), m);
        }
        lastInsertedMetric = m;
    };

    double findAndCheck (const std::string &topic)
    {
        auto it = knownMetrics.find(topic);
        if ( it == knownMetrics.cend() ) {
            return NAN;
        }
        else {
            int maxLiveTime = 5*60;
            int64_t currentTimestamp = ::time(NULL);
            if ( ( currentTimestamp - it->second._timestamp ) > maxLiveTime ) {
                knownMetrics.erase(it);
                return NAN;
            }
            else {
                return it->second._value;
            }
        }
    };

    double find (const std::string &topic) const
    {
        auto it = knownMetrics.find(topic);
        if ( it == knownMetrics.cend() ) {
            return NAN;
        }
        else {
            return it->second._value;
        }
    };

    int getMetricInfo (const std::string &topic, MetricInfo &metricInfo) const
    {
        auto it = knownMetrics.find(topic);
        if ( it == knownMetrics.cend() ) {
            return -1;
        }
        else {
            metricInfo = it->second;
            return 0;
        }
    };

    void removeOldMetrics()
    {
        int maxLiveTime = 5*60;
        int64_t currentTimestamp = ::time(NULL);

        for ( std::map<std::string, MetricInfo>::iterator iter = knownMetrics.begin(); iter != knownMetrics.end() ; /* empty */)
        {
            if ( ( currentTimestamp - iter->second._timestamp ) > maxLiveTime ) {
                knownMetrics.erase(iter++);
            }
            else {
                ++iter;
            }
        }
    };

    MetricInfo getLastMetric(void) const
    {
        return lastInsertedMetric;
    };


private:
    std::map<std::string, MetricInfo> knownMetrics;
    MetricInfo lastInsertedMetric;
};

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

class Rule {
public:
    std::string _lua_code;
    std::string _rule_name;
    std::string _element;
    std::string _severity;

    Rule(){};

    virtual int evaluate (const MetricList &metricList, PureAlert **pureAlert) const = 0;

    virtual bool isTopicInteresting(const std::string &topic) const = 0;

    virtual std::set<std::string> getNeededTopics(void) const = 0;

protected:

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

    friend Rule* readRule (std::ifstream &f);

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

    friend Rule* readRule (std::ifstream &f);

protected:

    lua_State* setContext (const MetricList &metricList) const
    {
        MetricInfo metricInfo;
        int rv = metricList.getMetricInfo (metricList.getLastMetric().generateTopic(), metricInfo);
        if ( rv != 0 ) {
            zsys_error ("last metric  wasn't found in the list of known metrics, code %d", rv);
            return NULL;
        }
        else {
            lua_State *lua_context = lua_open();
            lua_pushnumber(lua_context, metricInfo._value);
            lua_setglobal(lua_context, "value");
            zsys_info("Setting value to %lf\n", metricInfo._value);
            lua_pushstring(lua_context, metricInfo._element_name.c_str());
            lua_setglobal(lua_context, "element");
            zsys_info("Setting element to %s\n", metricInfo._element_name.c_str());
            return lua_context;
        }
    };

private:
    zrex_t *_rex;
    std::string _rex_str;
};

Rule* readRule (std::ifstream &f)
{
    // try catch TODO
    cxxtools::JsonDeserializer json(f);
    json.deserialize();
    const cxxtools::SerializationInfo *si = json.si();
    if ( si->findMember("in") ) {
        NormalRule *rule = new NormalRule();
        si->getMember("in") >>= rule->_in;
        si->getMember("element") >>= rule->_element;
        si->getMember("evaluation") >>= rule->_lua_code;
        si->getMember("rule_name") >>= rule->_rule_name;
        si->getMember("severity") >>= rule->_severity;
        return rule;
    }
    else {
        if ( si->findMember("in_rex") ) {
            RegexRule *rule = new RegexRule();
            si->getMember("in_rex") >>= rule->_rex_str;
            rule->_rex = zrex_new(rule->_rex_str.c_str());
            si->getMember("evaluation") >>= rule->_lua_code;
            si->getMember("rule_name") >>= rule->_rule_name;
            si->getMember("severity") >>= rule->_severity;
            return rule;
        }
        else
            return NULL;
    }
};

class AlertConfiguration{
public:
    AlertConfiguration(){};
    ~AlertConfiguration(){};

    // returns list of topics to be consumed
    std::set <std::string> readConfiguration(void)
    {
        std::set <std::string> result;

        cxxtools::Directory d(".");
        std::vector<PureAlert> emptyAlerts{};
        for ( const auto &fn : d)
        {
            if ( fn.length() < 5 ) {
                continue;
            }
            if ( fn.compare(fn.length() - 5, 5, ".rule") != 0 ) {
                continue;
            }
            std::ifstream f(fn);
            // TODO memory leak
            Rule *rule = readRule (f);
            // TODO check, that rule name is unique
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

//    std::vector <std::string> updateConfiguration(const Rule &rule);

    PureAlert* updateAlert (const Rule *rule, const PureAlert &pureAlert)
    {
        for ( auto &oneRuleAlerts : _alerts ) // this object can be changed -> no const
        {
            bool isSameRule = ( oneRuleAlerts.first->_rule_name == rule->_rule_name );
            if ( !isSameRule ) {
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


private:
    std::vector <std::pair<Rule*, std::vector<PureAlert> > > _alerts;
    std::vector <Rule*> _configs;
};

int main (int argc, char** argv) {

    mlm_client_t *client = mlm_client_new();
    mlm_client_connect (client, "ipc://@/malamute", 1000, argv[0]);
    mlm_client_set_producer(client, "ALERTS");

    AlertConfiguration alertConfiguration;
    std::set <std::string> subjectsToConsume = alertConfiguration.readConfiguration();
    zsys_info ("subjectsToConsume count: %d\n", subjectsToConsume.size());
    // Subscribe to all subjects
    for ( const auto &interestedSubject : subjectsToConsume ) {
        mlm_client_set_consumer(client, "BIOS", interestedSubject.c_str());
        zsys_info("Registered to receive '%s'\n", interestedSubject.c_str());
    }

    MetricList cache;

    while(!zsys_interrupted) {
        zmsg_t *zmessage = mlm_client_recv(client);
        if ( zmessage == NULL ) {
            continue;
        }
        char *type = NULL;
        char *element_src = NULL;
        char *value = NULL;
        char *unit = NULL;
        int64_t timestamp = 0;
        int rv = metric_decode (&zmessage, &type, &element_src, &value, &unit, &timestamp, NULL);
        if ( rv != 0 ) {
            zsys_info ("cannot decode metric, ignore message\n");
            continue;
        }
        char *end;
        double dvalue = strtod (value, &end);
        if (errno == ERANGE) {
            errno = 0;
            zsys_info ("cannot convert to double, ignore message\n");
            continue;
        }
        else if (end == value || *end != '\0') {
            zsys_info ("cannot convert to double, ignore message\n");
            continue;
        }

        std::string topic = mlm_client_subject(client);
        zsys_info("Got message '%s' with value %s\n", topic.c_str(), value);

        // Update cache with new value
        MetricInfo m (element_src, type, unit, dvalue, timestamp, "");
        cache.addMetric (m);
        cache.removeOldMetrics();

        for ( const auto &rule : alertConfiguration.getRules() )
        {
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
            alert_send (client, rule->_rule_name.c_str(), toSend->element.c_str(), toSend->timestamp, get_status_string(toSend->status), rule->_severity.c_str(), toSend->description.c_str());
        }
    }
    mlm_client_destroy(&client);
    return 0;
}
