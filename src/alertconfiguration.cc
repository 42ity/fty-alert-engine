/*
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
*/
#include <czmq.h>
extern int agent_alert_verbose;

#define zsys_debug1(...) \
    do { if (agent_alert_verbose) zsys_debug (__VA_ARGS__); } while (0);

#define RULES_SUBJECT "rfc-evaluator-rules"

#include <cxxtools/jsondeserializer.h>
#include <cxxtools/jsonserializer.h>
#include <cxxtools/directory.h>
#include <algorithm>
#include <fty_proto.h>
#include <malamute.h>

#include "alertconfiguration.h"

#include "metriclist.h"
#include "normalrule.h"
#include "thresholdrulesimple.h"
#include "thresholdruledevice.h"
#include "thresholdrulecomplex.h"
#include "regexrule.h"

int readRule (std::istream &f, RulePtr &rule)
{
    rule.reset();
    // TODO check, that rule actions have unique names (in the rule)
    // TODO check, that values have unique name (in the rule)
    try {
        cxxtools::SerializationInfo si2;
        {
            std::string json_string(std::istreambuf_iterator<char>(f), {});
            std::stringstream s(json_string);
            cxxtools::JsonDeserializer json(s);
            json.deserialize(si2);
            if (si2.memberCount () == 0)
                throw std::runtime_error ("empty input json document");
        }

        //MVY: SerializationInfo can contain more items, which is not what we
        //     want, pick the first one
        cxxtools::SerializationInfo si;
        si.addMember ("") <<= si2.getMember (0);

        std::unique_ptr <Rule> temp_rule;

        {
            temp_rule = std::unique_ptr<Rule> {new RegexRule()};
            int rv = temp_rule->fill (si);
            if ( rv == 0 ) {
                rule = std::move (temp_rule);
                return 0;
            }
            if ( rv == 2 )
                return 2;
        }

        {
            temp_rule = std::unique_ptr<Rule> {new ThresholdRuleSimple()};
            int rv = temp_rule->fill (si);
            if ( rv == 0 ) {
                rule = std::move (temp_rule);
                return 0;
            }
            if ( rv == 2 )
                return 2;
        }

        {
            temp_rule = std::unique_ptr<Rule> {new ThresholdRuleDevice()};
            int rv = temp_rule->fill (si);
            if ( rv == 0 ) {
                rule = std::move (temp_rule);
                return 0;
            }
            if ( rv == 2 )
                return 2;
        }

        {
            temp_rule = std::unique_ptr<Rule> {new ThresholdRuleComplex()};
            int rv = temp_rule->fill (si);
            if ( rv == 0 ) {
                rule = std::move (temp_rule);
                return 0;
            }
            if ( rv == 2 )
                return 2;
        }

        {
            temp_rule = std::unique_ptr<Rule> {new NormalRule()};
            int rv = temp_rule->fill (si);
            if ( rv == 0 ) {
                rule = std::move (temp_rule);
                return 0;
            }
            if ( rv == 2 )
                return 2;
        }
        zsys_error ("Cannot detect type of the rule");
        return 1;
    }
    catch ( const std::exception &e) {
        zsys_error ("Cannot parse JSON, ignore it. %s", e.what());
        return 1;
    }
}



std::set <std::string> AlertConfiguration::
    readConfiguration (void)
{
    // list of topics, that are needed to be consumed for rules
    std::set <std::string> result;

    try {
        if (!cxxtools::Directory::exists (_path)) cxxtools::Directory::create (_path);
        cxxtools::Directory d(_path);
        // every rule at the beggining has empty set of alerts
        std::vector<PureAlert> emptyAlerts{};
        for ( const auto &fn : d) {

            // we are interested only in files with names "*.rule"
            if ( fn.length() < 5 ) {
                continue;
            }
            if ( fn.compare(fn.length() - 5, 5, ".rule") != 0 ) {
                continue;
            }

            // read rule from the file
            std::ifstream f(d.path() + "/" + fn);
            zsys_debug1 ("processing_file: '%s'", (d.path() + "/" + fn).c_str());
            std::shared_ptr<Rule> rule;
            int rv = readRule (f, rule);
            if ( rv != 0 ) {
                // rule can't be read correctly from the file
                zsys_warning ("nothing to do");
                continue;
            }

            // ASSUMPTION: name of the file is the same as name of the rule
            // If they are different ignore this rule
            if ( !rule->hasSameNameAs (fn.substr(0, fn.length() -5)) ) {
                zsys_warning ("file name '%s' differs from rule name '%s', ignore it", fn.c_str(), rule->name ().c_str ());
                continue;
            }

            // ASSUMPTION: rules have unique names
            if ( haveRule (rule) ) {
                zsys_warning ("rule with name '%s' already known, ignore this one. File '%s'", rule->name().c_str(), fn.c_str());
                continue;
            }

            // record topics we are interested in
            for ( const auto &interestedTopic : rule->getNeededTopics() ) {
                result.insert (interestedTopic);
            }
            // add rule to the configuration
            _alerts.push_back (std::make_pair(std::move(rule), emptyAlerts));
            zsys_debug1 ("file '%s' readed correctly", fn.c_str());
        }
    } catch( std::exception &e ){
        zsys_error("Can't read configuration: %s", e.what());
        exit(1);
    }
    return result;
}

int AlertConfiguration::
    addRule (
        std::istream &newRuleString,
        std::set <std::string> &newSubjectsToSubscribe,
        std::vector <PureAlert> &alertsToSend,
        AlertConfiguration::iterator &it)
{
    // ASSUMPTIONS: newSubjectsToSubscribe and  alertsToSend are empty
    RulePtr temp_rule;
    int rv = readRule (newRuleString, temp_rule);
    if ( rv == 1 ) {
        zsys_error ("nothing created, json error");
        return -1;
    }
    if ( rv == 2 ) {
        zsys_error ("nothing created, lua error");
        return -5;
    }
    if ( haveRule (temp_rule) ) {
        zsys_error ("rule already exists");
        return -2;
    }

    std::vector<PureAlert> emptyAlerts{};
    try {
        temp_rule->save(getPersistencePath(), temp_rule->name () + ".rule");
    }
    catch (const std::exception& e) {
        zsys_error ("Error while saving file '%s': %s", std::string(getPersistencePath() + temp_rule->name () + ".rule").c_str (), e.what ());
        return -6;
    }
    // in any case we need to check new subjects
    for ( const auto &interestedTopic : temp_rule->getNeededTopics() ) {
        newSubjectsToSubscribe.insert (interestedTopic);
    }
    _alerts.push_back (std::make_pair(std::move(temp_rule), emptyAlerts));
    it = _alerts.end() - 1;
    // CURRENT: wait until new measurements arrive
    // TODO: reevaluate immidiately ( new Method )
    // reevaluate rule for every known metric
    //  ( requires more sophisticated approach: need to refactor evaluate back
    //  for 2 params + some logic here )
    return 0;
}

int AlertConfiguration::
    touchRule (
        const std::string &rule_name,
        std::vector <PureAlert> &alertsToSend)
{
    // find rule, that should be touched
    auto rule_to_update = _alerts.begin();
    while ( rule_to_update != _alerts.end() ) {
        if ( rule_to_update->first->hasSameNameAs (rule_name) ) {
            break;
        }
        ++rule_to_update;
    }
    // rule_to_update is an iterator to the rule+alerts
    if ( rule_to_update == _alerts.end() ) {
        zsys_error ("rule '%s' doesn't exist", rule_name.c_str());
        return -1;
    }

    // resolve found alerts
    for ( auto &oneAlert : rule_to_update->second ) {
        oneAlert._status = ALERT_RESOLVED;
        oneAlert._description = "Rule was changed implicitly";
        // put them into the list of alerts that had changed
        alertsToSend.push_back (oneAlert);
    }
    // clear alert cache
    rule_to_update->second.clear();

    return 0;
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
        zhash_t *aux = zhash_new();
        zhash_autofree (aux);
        zhash_insert (aux, "TTL", (void*) std::to_string (alert._ttl).c_str ());

        zmsg_t *msg = fty_proto_encode_alert (
            aux,
            rule_name.c_str(),
            alert._element.c_str(),
            alert._status.c_str(),
            alert._severity.c_str(),
            alert._description.c_str(),
            ::time (NULL),
            makeActionList(alert._actions).c_str()
        );
        if( msg ) {
            std::string atopic = rule_name + "/"
                + alert._severity + "@"
                + alert._element;
            mlm_client_send (client, atopic.c_str(), &msg);
            zsys_debug1 ("mlm_client_send (subject = '%s')", atopic.c_str());
        }
        zhash_destroy (&aux);
    }
}
static std::string
type_subtype2type_name (const std::string &type, const std::string &subtype)
{
    std::string type_name;
    std::string prefix ("__");
    if (subtype.c_str () != NULL)
        type_name = prefix + type + '_' + subtype + prefix;
    else
        type_name = prefix + type + prefix;
    return type_name;
}

static std::vector <std::string>
loadTemplates (const std::string &templates_dir, const std::string &type, const std::string &subtype)
{
    std::vector <std::string> templates;
    if (!cxxtools::Directory::exists (templates_dir)){
        zsys_info ("Rule templates '%s' dir does not exist", templates_dir.c_str ());
        return templates;
    }
    std::string type_name = type_subtype2type_name (type, subtype);
    cxxtools::Directory d (templates_dir);
    for ( const auto &fn : d) {
        if ( fn.find(type_name.c_str())!= std::string::npos){
            zsys_debug("match %s", fn.c_str());
            // read the template rule from the file
            std::ifstream f(d.path() + "/" + fn);
            std::string str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            templates.push_back(str);
        }
    }
    return templates;
}

static std::string
replaceTokens( const std::string &text, const std::string &pattern, const std::string &replacement) {
    std::string result = text;
    size_t pos = 0;
    while( ( pos = result.find(pattern, pos) ) != std::string::npos){
        result.replace(pos, pattern.length(), replacement);
        pos += replacement.length();
    }
    return result;
}

//go through all the rule templates, create rules correspoding to the new asset
bool AlertConfiguration::
    generateRulesForAsset (
        mlm_client_t *client,
        const std::string &type,
        const std::string &subtype,
        const std::string &name)
{
    bool result = true;
    std::set <std::string> newSubjectsToSubscribe;
    std::vector <PureAlert> alertsToSend;
    AlertConfiguration::iterator new_rule_it;
    std::vector <std::string> templates = loadTemplates (_templates_path, type, subtype);
    for ( auto &templat : templates) {
        std::string rule = replaceTokens (templat,"__name__",name);
        zsys_debug("creating rule :\n %s", rule.c_str());
        std::istringstream newRule (rule.c_str ());
        int rv = addRule (newRule,
                        newSubjectsToSubscribe,
                        alertsToSend,
                        new_rule_it);
        zmsg_t *reply = zmsg_new ();
        switch (rv) {
        case -2:
        {
            // rule exists
            zsys_debug1 ("rule already exists");
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, "ALREADY_EXISTS");

            mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
            result &= false;
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
            zmsg_addstr (reply, rule.c_str ());
            mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);

            // send updated alert
            send_alerts (client, alertsToSend, new_rule_it->first->name ());
            result &= true;
        }
        case -5:
        {
            zsys_debug1 ("rule has bad lua");
            // error during the rule creation (lua)
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, "BAD_LUA");

            mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
            result &= false;
        }
        case -6:
        {
            zsys_debug1 ("internal error");
            // error during the rule creation (lua)
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, "Internal error - operating with storage/disk failed.");

            mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
            result &= false;
        }
        default:
            // error during the rule creation
            zsys_debug1 ("default bad json");
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, "BAD_JSON");

            mlm_client_sendto (client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker (client), 1000, &reply);
            result &= false;
        }
    }

    return result;
}
int AlertConfiguration::
    removeRulesForAsset (
        const std::string &asset_name,
        std::vector <PureAlert> &alertsToSend)
{
    for (auto &oneRuleAlerts : _alerts)
    {
        if (oneRuleAlerts.first->_element == asset_name) {
            std::string rule_name = oneRuleAlerts.first->name ();
            // remove rule from persistent storage
            int rv = oneRuleAlerts.first->remove (getPersistencePath());
            if (rv != 0) {
                zsys_error ("rule '%s' could not be removed", rule_name.c_str());
                return -1;
            }
            // resolve found alerts
            for (auto &oneAlert : oneRuleAlerts.second) {
                oneAlert._status = ALERT_RESOLVED;
                oneAlert._description = "Rule changed";
                // put them into the list of alerts that changed
                alertsToSend.push_back (oneAlert);
            }
            // clear cache
            oneRuleAlerts.second.clear ();
            // remove rule
            oneRuleAlerts.first.reset ();
        }
    }

    // remove all entries concerning 'asset_name'
    _alerts.erase (std::remove_if (_alerts.begin(),
                                _alerts.end(),
                                [&asset_name] (std::pair <RulePtr, std::vector<PureAlert>> elem) {  return (elem.first->_element == asset_name); }
                                ),
                    _alerts.end());
    return 0;
}

void AlertConfiguration::
    resolveAlertsForAsset (
        const std::string &asset_name,
        std::vector <PureAlert> &alertsToSend)
{
    for (auto &oneRuleAlerts : _alerts)
        if (oneRuleAlerts.first->_element == asset_name)
            for (auto &oneAlert : oneRuleAlerts.second) {
                oneAlert._status = ALERT_RESOLVED;
                oneAlert._description = "Rule changed";
                // put them into the list of alerts that changed
                alertsToSend.push_back (oneAlert);
            }
}


void AlertConfiguration::
    evaluateRulesForAsset (
        mlm_client_t *client,
        const std::string &asset_name,
        const MetricList &knownMetricValues)
{
    for (auto &oneRuleAlerts : _alerts)
    {
        auto &rule = oneRuleAlerts.first;
        if (rule->_element == asset_name) {
            try {
                PureAlert pureAlert;
                int rv = rule->evaluate (knownMetricValues, pureAlert);
                if ( rv != 0 ) {
                    zsys_error (" ### Cannot evaluate the rule '%s'", rule->name().c_str());
                    continue;
                }

                PureAlert alertToSend;
                rv = updateAlert (rule, pureAlert, alertToSend);
                if ( rv == -1 ) {
                    zsys_debug1 (" ### alert updated, nothing to send");
                    // nothing to send
                    continue;
                }
                send_alerts (client, {alertToSend}, rule->name ());
            }
            catch ( const std::exception &e) {
                zsys_error ("CANNOT evaluate rule, because '%s'", e.what());
            }
        }
    }
}

int AlertConfiguration::
    updateRule (
        std::istream &newRuleString,
        const std::string &old_name,
        std::set <std::string> &newSubjectsToSubscribe,
        std::vector <PureAlert> &alertsToSend,
        AlertConfiguration::iterator &it)
{
    // ASSUMPTIONS: newSubjectsToSubscribe and  alertsToSend are empty
    // need to find out if rule exists already or not
    if ( !haveRule (old_name) ) {
        zsys_error ("rule doesn't exist");
        return -2;
    }

    RulePtr temp_rule;
    int rv = readRule (newRuleString, temp_rule);
    if ( rv == 1 ) {
        zsys_error ("nothing to update, json error");
        return -1;
    }
    if ( rv == 2 ) {
        zsys_error ("nothing to update, lua error");
        return -5;
    }
    // if name of the rule changed, then
    // need to find out if rule with new rulename exists already or not
    if ( ! temp_rule->hasSameNameAs(old_name) && haveRule (temp_rule->name()) )
    {
        // rule with new old_name
        zsys_error ("Rule with such name already exists");
        return -3;
    }

    // find rule, that should be updated
    auto rule_to_update = _alerts.begin();
    while ( rule_to_update != _alerts.end() ) {
        if ( rule_to_update->first->hasSameNameAs (old_name) ) {
            break;
        }
        ++rule_to_update;
    }
    // rule_to_update is an iterator to the rule+alerts

    // try to save the file, first
    try {
        temp_rule->save(getPersistencePath(), temp_rule->name () + ".rule.new");
    }
    catch (const std::exception& e) {
        // if error happend, we didn't lose any previous data
        zsys_error ("Error while saving file '%s': %s", std::string(getPersistencePath() + temp_rule->name () + ".rule.new").c_str (), e.what ());
        return -6;
    }
    // as we successfuly saved the new file, we can try to remove old one
    rv = rule_to_update->first->remove (getPersistencePath());
    std::string rule_removed_name = rule_to_update->first->name ();
    if ( rv != 0 ) {
        zsys_error ("Old rule wasn't removed, but new one stored with postfix '.new' and is not used yet. Rename *.rule.new file to *.rule, remove old .rule and then manually and restart the daemon", rule_removed_name.c_str ());
        return -6;
    }
    // as we successfuly removed old rule, we can rename new rule to the right name
    rv = std::rename (std::string (getPersistencePath()).append (rule_removed_name).append(".rule.new").c_str (),
            std::string (getPersistencePath()).append (rule_removed_name).append(".rule").c_str ());
    if ( rv != 0 ) {
        zsys_error ("Error renaming .rule.new to .new for '%s'. Rename *.rule.new file to *.rule and then manually and restart the daemon", rule_removed_name.c_str ());
        return -6;
    }
    // so, in the files now everything ok
    // and we need to fix information in the memory

    // resolve found alerts
    for ( auto &oneAlert : rule_to_update->second ) {
        oneAlert._status = ALERT_RESOLVED;
        oneAlert._description = "Rule changed";
        // put them into the list of alerts that changed
        alertsToSend.push_back (oneAlert);
    }
    // clear cache
    rule_to_update->second.clear();
    // remove old rule
    rule_to_update->first.reset ();
    // remove entire entry
    _alerts.erase (rule_to_update);

    // find new topics to subscribe
    std::vector<PureAlert> emptyAlerts{};
    // As we changed the rule, we need to check new subjects
    for ( const auto &interestedTopic : temp_rule->getNeededTopics() ) {
        newSubjectsToSubscribe.insert (interestedTopic);
    }
    // put new rule with empty alerts into the cache
    _alerts.push_back (std::make_pair(std::move(temp_rule), emptyAlerts));
    it = _alerts.end() - 1;
    // CURRENT: wait until new measurements arrive
    // TODO: reevaluate immidiately ( new Method )
    // reevaluate rule for every known metric
    //  ( requires more sophisticated approach: need to refactor evaluate back
    //  for 2 params + some logic here )
    return 0;
}

int AlertConfiguration::
    updateAlert (
        const RulePtr &rule,
        const PureAlert &pureAlert,
        PureAlert &alert_to_send)
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
                    zsys_debug1("RULE '%s' : OLD ALERT starts again for element '%s' with description '%s'\n", oneRuleAlerts.first->name().c_str(), oneAlert._element.c_str(), oneAlert._description.c_str());
                }
                else {
                    // Found alert is still active -> it is the same alert
                    // If alert is still ongoing, it doesn't mean, that every attribute of alert stayed the same
                    oneAlert._description = pureAlert._description;
                    oneAlert._severity = pureAlert._severity;
                    oneAlert._actions = pureAlert._actions;
                    zsys_debug1("RULE '%s' : ALERT is ALREADY ongoing for element '%s' with description '%s'\n", oneRuleAlerts.first->name().c_str(), oneAlert._element.c_str(), oneAlert._description.c_str());
                }
                // in both cases we need to send an alert
                alert_to_send = PureAlert(oneAlert);
                return 0;
            }
            if ( pureAlert._status == ALERT_RESOLVED ) {
                if ( oneAlert._status != ALERT_RESOLVED ) {
                    // Found alert is not resolved. -> resolve it
                    oneAlert._status = pureAlert._status;
                    oneAlert._timestamp = pureAlert._timestamp;
                    oneAlert._description = pureAlert._description;
                    oneAlert._severity = pureAlert._severity;
                    oneAlert._actions = pureAlert._actions;
                    zsys_debug1("RULE '%s' : ALERT is resolved for element '%s' with description '%s'\n", oneRuleAlerts.first->name().c_str(), oneAlert._element.c_str(), oneAlert._description.c_str());
                    alert_to_send = PureAlert(oneAlert);
                    return 0;
                }
                else {
                    // alert was already resolved -> nothing to do
                    return -1;
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
                zsys_debug1("RULE '%s' : ALERT is NEW for element '%s' with description '%s'\n", oneRuleAlerts.first->name().c_str(), pureAlert._element.c_str(), pureAlert._description.c_str());
                alert_to_send = PureAlert(pureAlert);
                return 0;
            }
            else
            {
                // nothing to do, no need to add to the list resolved alerts
            }
        }
    } // end of processing one rule
    return -1;
}


int AlertConfiguration::
    updateAlertState (
        const char *rule_name,
        const char *element_name,
        const char *new_state,
        PureAlert &pureAlert)
{
    if ( !PureAlert::isStatusKnown(new_state) ) {
        zsys_error ("Unknown new status, ignore it");
        return -5;
    }
    if ( strcmp(new_state, ALERT_RESOLVED) == 0 ) {
        zsys_error ("User can't resolve alert manually");
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
                zsys_error ("state of RESOLVED alert cannot be chaged manually");
                return -1;
            }
            oneAlert._status = new_state;
            pureAlert = oneAlert;
            return 0;
        }
    }
    zsys_error ("Cannot acknowledge alert, because it doesn't exist");
    return -4;
}
