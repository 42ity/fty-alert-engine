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

#include <cxxtools/jsondeserializer.h>
#include <cxxtools/jsonserializer.h>
#include <cxxtools/directory.h>
#include "metriclist.h"
#include "normalrule.h"
#include "thresholdrulesimple.h"
#include "thresholdrulecomplex.h"
#include "regexrule.h"

#include "alertconfiguration.h"
// It tries to simply parse and read JSON
Rule* readRule (std::istream &f)
{
    // TODO check, that rule actions have unique names (in the rule)
    // TODO check, that values have unique name (in the rule)
    // TODO check, that lua function is correct
    Rule *rule = NULL;
    try {
        // TODO this appoach can cause, that "Json" repsesentation is HUGE file because of witespaces
        std::string json_string(std::istreambuf_iterator<char>(f), {});
        std::stringstream s(json_string);
        cxxtools::JsonDeserializer json(s);
        json.deserialize();
        // TODO too complex method, need to split it
        // TODO not very good use of fill function. work in progress

        Rule *rule = new RegexRule();
        int rv = rule->fill (json, json_string);
        if ( rv == 0 )
            return rule;
        delete rule;
        
        rule = new ThresholdRuleSimple();
        rv = rule->fill (json, json_string);
        if ( rv == 0 )
            return rule;
        delete rule; 

        rule = new ThresholdRuleComplex();
        rv = rule->fill (json, json_string);
        if ( rv == 0 )
            return rule;
        delete rule; 

        rule = new NormalRule();
        rv = rule->fill (json, json_string);
        if ( rv == 0 )
            return rule;
        delete rule; 

        zsys_error ("Cannot detect type of the rule, ignore it");
        return NULL;
    }
    catch ( const std::exception &e) {
        zsys_error ("Cannot parse JSON, ignore it. %s", e.what());
        delete rule;
        return NULL;
    }
}



std::set <std::string> AlertConfiguration::
    readConfiguration (void)
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
        std::ifstream f(d.path() + "/" + fn);
        zsys_info ("processing_file: '%s'", (d.path() + "/" + fn).c_str());
        Rule *rule = readRule (f);
        if ( rule == NULL ) {
            // rule can't be read correctly from the file
            zsys_info ("nothing to do");
            continue;
        }

        // ASSUMPTION: name of the file is the same as name of the rule
        // If they are different ignore this rule
        if ( !rule->hasSameNameAs (fn.substr(0, fn.length() -5)) ) {
            zsys_info ("file name '%s' differs from rule name '%s', ignore it", fn.c_str(), rule->name ().c_str ());
            delete rule;
            continue;
        }

        // ASSUMPTION: rules have unique names
        if ( haveRule (rule) ) {
            zsys_info ("rule with name '%s' already known, ignore this one. File '%s'", rule->name().c_str(), fn.c_str());
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
}

int AlertConfiguration::
    addRule (
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
    if ( haveRule (*newRule) ) {
        zsys_info ("rule already exists");
        return -2;
    }
    std::vector<PureAlert> emptyAlerts{};
    _alerts.push_back (std::make_pair(*newRule, emptyAlerts));
    _configs.push_back (*newRule);
    (*newRule)->save(getPersistencePath());
    // in any case we need to check new subjects
    for ( const auto &interestedTopic : (*newRule)->getNeededTopics() ) {
        newSubjectsToSubscribe.insert (interestedTopic);
    }
    // CURRENT: wait until new measurements arrive
    // TODO: reevaluate immidiately ( new Method )
    // reevaluate rule for every known metric
    //  ( requires more sophisticated approach: need to refactor evaluate back for 2 params + some logic here )
    return 0;
}

int AlertConfiguration::
    updateRule (
        std::istream &newRuleString,
        const std::string &rule_name,
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
    if ( !haveRule (rule_name) )
    {
        zsys_info ("rule doesn't exist");
        return -2;
    }
    // need to find out if rule exists already or not
    if ( haveRule ((*newRule)->name()) )
    {
        // rule with new rule_name
        zsys_info ("Rule with such name already exists");
        return -3;
    }
    // find alerts, that should be resolved
    for ( auto &oneRuleAlerts: _alerts ) {
        if ( ! oneRuleAlerts.first->hasSameNameAs (rule_name) ) {
            continue;
        }
        // so we finally found a list of alerts
        // resolve found alerts
        for ( auto &oneAlert : oneRuleAlerts.second ) {
            oneAlert._status = ALERT_RESOLVED;
            oneAlert._description = "Rule changed";
            // put them into the list of alerts that changed
            alertsToSend.push_back (oneAlert);
        }
        oneRuleAlerts.second.clear();
        // update rule
        // This part is ugly, as there are duplicate pointers
        for ( auto &oneRule: _configs ) {
            if ( oneRule->hasSameNameAs (rule_name) ) {
                // -- free memory used by oldone
                int rv = oneRule->remove(getPersistencePath());
                zsys_info ("remove rv = %d", rv);
                delete oneRule;
                oneRule = *newRule;
                break; // rule_name is unique
            }
        }
        // -- use new rule
        oneRuleAlerts.first = *newRule;
    }
    // in any case we need to check new subjects
    for ( const auto &interestedTopic : (*newRule)->getNeededTopics() ) {
        newSubjectsToSubscribe.insert (interestedTopic);
    }
    (*newRule)->save(getPersistencePath());
    // CURRENT: wait until new measurements arrive
    // TODO: reevaluate immidiately ( new Method )
    // reevaluate rule for every known metric
    //  ( requires more sophisticated approach: need to refactor evaluate back for 2 params + some logic here )
    return 0;
}

PureAlert* AlertConfiguration::
    updateAlert (
        const Rule *rule,
        const PureAlert &pureAlert)
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
            bool isSameAlert = ( pureAlert._element == oneAlert._element );
            if ( !isSameAlert ) {
                continue;
            }
            // we found the alert
            isAlertFound = true;
            if ( pureAlert._status == ALERT_START ) {
                if ( oneAlert._status == ALERT_RESOLVED ) {
                    // Found alert is old. This is new one
                    oneAlert._status = pureAlert._status;
                    oneAlert._timestamp = pureAlert._timestamp;
                    oneAlert._description = pureAlert._description;
                    oneAlert._severity = pureAlert._severity;
                    oneAlert._actions = pureAlert._actions;
                    // element is the same -> no need to update the field
                    zsys_info("RULE '%s' : OLD ALERT starts again for element '%s' with description '%s'\n", oneRuleAlerts.first->name().c_str(), oneAlert._element.c_str(), oneAlert._description.c_str());
                }
                else {
                    // Found alert is still active -> it is the same alert
                    // If alert is still ongoing, it doesn't mean, that every attribute of alert stayed the same
                    oneAlert._description = pureAlert._description;
                    oneAlert._severity = pureAlert._severity;
                    oneAlert._actions = pureAlert._actions;
                    zsys_info("RULE '%s' : ALERT is ALREADY ongoing for element '%s' with description '%s'\n", oneRuleAlerts.first->name().c_str(), oneAlert._element.c_str(), oneAlert._description.c_str());
                }
                // in both cases we need to send an alert
                PureAlert *toSend = new PureAlert(oneAlert);
                return toSend;
            }
            if ( pureAlert._status == ALERT_RESOLVED ) {
                if ( oneAlert._status != ALERT_RESOLVED ) {
                    // Found alert is not resolved. -> resolve it
                    oneAlert._status = pureAlert._status;
                    oneAlert._timestamp = pureAlert._timestamp;
                    oneAlert._description = pureAlert._description;
                    oneAlert._severity = pureAlert._severity;
                    oneAlert._actions = pureAlert._actions;
                    zsys_info("RULE '%s' : ALERT is resolved for element '%s' with description '%s'\n", oneRuleAlerts.first->name().c_str(), oneAlert._element.c_str(), oneAlert._description.c_str());
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
            if ( pureAlert._status != ALERT_RESOLVED )
            {
                oneRuleAlerts.second.push_back(pureAlert);
                zsys_info("RULE '%s' : ALERT is NEW for element '%s' with description '%s'\n", oneRuleAlerts.first->name().c_str(), pureAlert._element.c_str(), pureAlert._description.c_str());
                PureAlert *toSend = new PureAlert(pureAlert);
                return toSend;
            }
            else
            {
                // nothing to do, no need to add to the list resolved alerts
            }
        }
    } // end of processing one rule
    return NULL; //make compiler happy - why this finctions returns smthng?
}


int AlertConfiguration::
    updateAlertState (
        const char *rule_name,
        const char *element_name,
        const char *new_state,
        PureAlert &pureAlert)
{
    if ( !PureAlert::isStatusKnown(new_state) ) {
        zsys_info ("Unknown new status, ignore it");
        return -5;
    }
    if ( strcmp(new_state, ALERT_RESOLVED) == 0 ) {
        zsys_info ("User can't resolve alert manually");
        return -2;
    }
    for ( auto &oneRuleAlerts : _alerts )
    {
        if ( !oneRuleAlerts.first->hasSameNameAs (rule_name) ) {
            continue;
        }
        // we found the rule
        for ( auto &oneAlert : oneRuleAlerts.second )
        {
            bool isSameAlert = ( oneAlert._element == element_name );
            if ( !isSameAlert ) {
                continue;
            }
            // we found the alert
            if ( oneAlert._status == ALERT_RESOLVED ) {
                zsys_info ("state of RESOLVED alert cannot be chaged manually");
                return -1;
            }
            oneAlert._status = new_state;
            pureAlert = oneAlert;
            return 0;
        }
    }
    zsys_info ("Cannot acknowledge alert, because it doesn't exist");
    return -4;
}

std::vector<Rule*> AlertConfiguration::
    getRulesByType (
        const std::type_info &type_id)
{
    /* How this works: https://msdn.microsoft.com/ru-ru/library/fyf39xec.aspx
       Derived* pd = new Derived;
       Base* pb = pd;
       cout << typeid( pb ).name()  << endl;   //prints "class Base *"
       cout << typeid( *pb ).name() << endl;   //prints "class Derived"
       cout << typeid( pd ).name()  << endl;   //prints "class Derived *"
       cout << typeid( *pd ).name() << endl;   //prints "class Derived"
       */
    std::vector<Rule *> result;
    for ( auto rule : _configs) {
        //zsys_info("T type '%s'", typeid(*rule).name() );
        if( type_id == typeid(Rule) || type_id == typeid(*rule) ) {
            result.push_back(rule);
        }
    }
    return result;
}

Rule* AlertConfiguration::
    getRuleByName (
        const std::string &name)
{
    // TODO: make some map of names to avoid o(n)?
    // Return iterator rather than pointer?
    for (auto rule : _configs) {
        if( rule->hasSameNameAs( name ) ) return rule;
    }
    return NULL;
}
