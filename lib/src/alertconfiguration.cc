/*
Copyright (C) 2014 - 2020 Eaton

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

#include "alertconfiguration.h"
#include "templateruleconfigurator.h"
#include "autoconfig.h"

#include "rule/regexrule.h"
#include "rule/thresholdrulesimple.h"
#include "rule/thresholdrulecomplex.h"
#include "rule/normalrule.h"

#include <fty_log.h>
#include <fty_common_json.h>
#include <cxxtools/serializationinfo.h>
#include <czmq.h>
#include <algorithm>
#include <filesystem>
#include <istream>

int readRule(const std::string& jsonPayload, RulePtr& rule)
{
    rule.reset();

    // TODO check, that rule actions have unique names (in the rule)
    // TODO check, that values have unique name (in the rule)
    try {
        // json w/ unique member
        cxxtools::SerializationInfo si;
        JSON::readFromString(jsonPayload, si);
        if (si.memberCount() == 0)
            { throw std::runtime_error("empty member json document"); }
        if (si.memberCount() != 1)
            { throw std::runtime_error("multiple members json document"); }

        // try to parse/fill a new rule from si
        // returns 0 if success (rule is set as recognized)
        // returns 2 if error (incompatible or Lua error)
        // else do nothing (unrecognized)
        #define TRY_RULE_FILL(newRule) \
        { \
            std::unique_ptr<Rule> tmpRule{newRule}; \
            switch (tmpRule->fill(si)) { \
                case 0: \
                    rule = std::move(tmpRule); \
                    logDebug("recognize rule named '{}' ({})", rule->name(), rule->clazz()); \
                    return 0; \
                case 2: \
                    return 2; \
                default:; \
            } \
        }

        TRY_RULE_FILL(new RegexRule());
        TRY_RULE_FILL(new ThresholdRuleSimple());
        TRY_RULE_FILL(new ThresholdRuleComplex());
        TRY_RULE_FILL(new NormalRule());

        // unrecognized rule
        log_error("readRule: can't recognize the type of the rule");
    }
    catch (const std::exception& e) {
        log_error("readRule: can't parse JSON (e: %s)", e.what());
    }

    return 1; // read failed (unrecognized or internal/json error)
}

std::set<std::string> AlertConfiguration::readConfiguration()
{
    // list of topics, that are needed to be consumed for rules
    std::set<std::string> result;

    log_debug("read rule files from '%s'", _path.c_str());

    try {
        if (!std::filesystem::exists(_path)) {
            log_debug("create directory '%s'", _path.c_str());
            std::filesystem::create_directories(_path);
        }
        std::filesystem::path dir(_path);

        // every rule at the begining has empty set of alerts
        for (const auto& fn : std::filesystem::directory_iterator(dir)) {

            // filter on .rule files
            if (fn.path().extension() != ".rule") {
                continue;
            }

            const std::string fname{fn.path().filename()};

            // read rule from the file
            std::unique_ptr<Rule> rule{nullptr};
            {
                log_debug("processing file: '%s'", fn.path().c_str());
                std::ifstream ifs{fn.path()};
                const std::string json{std::istreambuf_iterator<char>(ifs), {}};
                int r = readRule(json, rule);
                if (r != 0) {
                    // rule can't be read correctly from the file
                    log_warning("'%s' ignored (r = %d)", fname.c_str(), r);
                    continue;
                }
            }

            const std::string rulename{rule->name()};

            // ASSUMPTION: name of the file is the same as name of the rule
            // If they are different ignore this rule (5 = strlen(".rule"))
            if (rulename != fname.substr(0, fname.length() - 5)) {
                log_warning("'%s' differs from rule name '%s', ignore it", fname.c_str(), rulename.c_str());
                continue;
            }

            // ASSUMPTION: rules have unique names
            if (haveRule(rule)) {
                log_warning("rule '%s' already known & ignoree (file: '%s')", rulename.c_str(), fname.c_str());
                continue;
            }

            // record topics we are interested in
            for (const auto& interestedTopic : rule->getNeededTopics()) {
                result.insert(interestedTopic);

                auto _it_metrics = _metrics_alerts_map.find(interestedTopic);
                if (_it_metrics != _metrics_alerts_map.end()) {
                    _it_metrics->second.push_back(rulename);
                }
                else {
                    _metrics_alerts_map.insert(std::make_pair(interestedTopic, std::vector<std::string>{rulename}));
                }
            }

            // add rule to the configuration
            const std::vector<PureAlert> emptyAlerts;
            _alerts_map.insert(std::make_pair(rulename, std::make_pair(std::move(rule), emptyAlerts)));

            log_debug("file '%s' read correctly", fname.c_str());
        }
    }
    catch (const std::exception& e) {
        log_fatal("EXIT_FAILURE - Can't read %s configuration (e: %s)", _path.c_str(), e.what());
        exit(EXIT_FAILURE); // ZZZ EXIT
    }

    return result;
}

int AlertConfiguration::addRule(
    const std::string& json,
    std::set<std::string>& newSubjectsToSubscribe,
    std::vector<PureAlert>& /* alertsToSend */,
    AlertConfiguration::iterator& it
)
{
    // ASSUMPTIONS: newSubjectsToSubscribe is empty
    if (!newSubjectsToSubscribe.empty()) {
        log_debug("ERROR ASSUMPTION: newSubjectsToSubscribe is empty");
        newSubjectsToSubscribe.clear();
    }

    RulePtr temp_rule{nullptr};
    int r = readRule(json, temp_rule);
    if (r != 0) { // failed
        switch (r) {
            case 1:
                log_error("nothing created, json error"); // json error !?
                return -1;
            case 2:
                log_error("nothing created, Lua error");
                return -5;
            default:;
        }
        log_error("nothing created, error: %d", r);
        return -1;
    }

    const std::string rulename{temp_rule->name()};

    // PQSWMBT-3723, don't instanciate sensor temp./humidity rules directly
    if ((rulename.find("humidity.default@sensor-") == 0) // starts with...
        || (rulename.find("temperature.default@sensor-") == 0)) {
        log_debug("rule instanciation rejected (%s)", rulename.c_str());
        return -100;
    }
    // end PQSWMBT-3723

    // PQSWMBT-4921 Xphase rule exceptions (see templateruleconfigurator.cc)
    const std::string asset = rulename.substr(rulename.find("@") + 1);
    if (!ruleXphaseIsApplicable(rulename, getAssetInfoFromAutoconfig(asset))) {
        log_debug("Xphase rule instanciation rejected (%s)", rulename.c_str());
        return -101;
    }
    // end PQSWMBT-4921

    log_info("addRule %s", rulename.c_str());

    if (haveRule(temp_rule)) {
        log_debug("rule %s already exists", rulename.c_str());
        return -2;
    }

    try {
        temp_rule->save(getPersistencePath(), rulename + ".rule");
    }
    catch (const std::exception& e) {
        const std::string filename{getPersistencePath() + rulename + ".rule"};
        log_error("Error saving file '%s' (e: %s)", filename.c_str(), e.what());
        return -6;
    }

    // in any case we need to check new subjects
    for (const auto& interestedTopic : temp_rule->getNeededTopics()) {
        //log_debug("interestedTopic:", interestedTopic.c_str());
        newSubjectsToSubscribe.insert(interestedTopic);

        auto _it_metrics = _metrics_alerts_map.find(interestedTopic);
        if (_it_metrics != _metrics_alerts_map.end()) {
            log_debug("_it_metrics %s: add rule %s ", _it_metrics->first.c_str(), rulename.c_str());
            _it_metrics->second.push_back(rulename);
        }
        else {
            log_debug("_metrics_alerts_map insert: topic: %s, rule %s ", interestedTopic.c_str(), rulename.c_str());
            _metrics_alerts_map.insert(std::make_pair(interestedTopic, std::vector<std::string>{rulename}));
        }
    }

    _alerts_map.insert(std::make_pair(rulename, std::make_pair(std::move(temp_rule), std::vector<PureAlert>{}/*empty*/)));

    it = _alerts_map.find(rulename);

    return 0;
}

int AlertConfiguration::touchRule(const std::string& rule_name, std::vector<PureAlert>& alertsToSend)
{
    // find rule, that should be touched
    // rule_to_update is an iterator to the rule+alerts
    auto rule_to_update = _alerts_map.find(rule_name);
    if (rule_to_update == _alerts_map.end()) {
        log_error("rule '%s' doesn't exist", rule_name.c_str());
        return -1;
    }

    // resolve found alerts
    for (auto& oneAlert : rule_to_update->second.second) {
        oneAlert._status = ALERT_RESOLVED;
        oneAlert._description = "Rule was changed implicitly";
        // put them into the list of alerts that had changed
        alertsToSend.push_back(oneAlert);
    }

    // clear alert cache
    rule_to_update->second.second.clear();

    return 0;
}

int AlertConfiguration::updateRule(
    const std::string& newRuleString,
    const std::string& old_name,
    std::set<std::string>& newSubjectsToSubscribe, std::vector<PureAlert>& alertsToSend,
    AlertConfiguration::iterator& it
)
{
    // ASSUMPTIONS: newSubjectsToSubscribe and alertsToSend are empty
    if (!newSubjectsToSubscribe.empty()) {
        log_debug("ERROR ASSUMPTION: newSubjectsToSubscribe is empty");
        newSubjectsToSubscribe.clear();
    }

    if (!alertsToSend.empty()) {
        log_debug("ERROR ASSUMPTION: alertsToSend is empty");
        alertsToSend.clear();
    }

    // need to find out if rule exists already or not
    if (old_name.empty()) {
        log_error("rule old_name is empty");
        return -2;
    }
    if (!haveRule(old_name)) {
        log_error("rule doesn't exist");
        return -2;
    }

    RulePtr temp_rule{nullptr};
    int r = readRule(newRuleString, temp_rule);
    if (r != 0) { // failed
        switch (r) {
            case 1:
                log_error("nothing created, json error"); // json error !?
                return -1;
            case 2:
                log_error("nothing created, Lua error");
                return -5;
            default:;
        }
        log_error("nothing created, error: %d", r);
        return -1;
    }

    // if name of the rule changed, then
    // need to find out if rule with new rulename exists already or not
    if ((temp_rule->name() != old_name) && haveRule(temp_rule->name())) {
        // rule with new old_name
        log_error("Rule with such name already exists");
        return -3;
    }

    // find rule, that should be updated
    auto rule_to_update = _alerts_map.find(old_name);

    // try to save the file, first
    try {
        temp_rule->save(getPersistencePath(), temp_rule->name() + ".rule.new");
    }
    catch (const std::exception& e) {
        // if error happend, we didn't lose any previous data
        std::string filename = getPersistencePath() + temp_rule->name() + ".rule.new";
        log_error("Error while saving file '%s': %s", filename.c_str(), e.what());
        return -6;
    }

    // as we successfuly saved the new file, we can try to remove old one
    r = rule_to_update->second.first->remove(getPersistencePath());
    std::string rule_removed_name = rule_to_update->second.first->name();
    if (r != 0) {
        log_error(
            "Old rule wasn't removed, but new one stored with postfix '.new' and is not used yet. Rename *.rule.new "
            "file to *.rule, remove old .rule and then manually and restart the daemon",
            rule_removed_name.c_str());
        return -6;
    }

    // as we successfuly removed old rule, we can rename new rule to the right name
    r = std::rename(getPersistencePath().append(rule_removed_name).append(".rule.new").c_str(),
        getPersistencePath().append(rule_removed_name).append(".rule").c_str());
    if (r != 0) {
        log_error(
            "Error renaming .rule.new to .new for '%s'. Rename *.rule.new file to *.rule and then manually and restart the daemon",
            rule_removed_name.c_str());
        return -6;
    }

    // here, everything ok with files
    // and we need to fix information in the memory

    // resolve found alerts
    for (auto& oneAlert : rule_to_update->second.second) {
        oneAlert._status = ALERT_RESOLVED;
        // put them into the list of alerts that changed
        alertsToSend.push_back(oneAlert);
    }

    for (const auto& interestedTopic : rule_to_update->second.first->getNeededTopics()) {
        auto _it_metrics = _metrics_alerts_map.find(interestedTopic);
        if (_it_metrics != _metrics_alerts_map.end()) {
            int it_pos = 0;
            for (auto& it_rule_in_metric : _it_metrics->second) {
                if (it_rule_in_metric == rule_removed_name) {
                    _it_metrics->second.erase(_it_metrics->second.begin() + it_pos);
                    break;
                }
                it_pos++;
            }
        }
        else {
            // should not happened
            log_error("Remove rule %s with metric %s who was never been add.",
                rule_removed_name.c_str(), interestedTopic.c_str());
        }
    }

    // clear cache
    rule_to_update->second.second.clear();
    // remove old rule
    rule_to_update->second.first.reset();
    // remove entire entiry
    _alerts_map.erase(rule_to_update);

    // find new topics to subscribe
    std::string rulename = temp_rule->name();

    // As we changed the rule, we need to check new subjects
    for (const auto& interestedTopic : temp_rule->getNeededTopics()) {
        newSubjectsToSubscribe.insert(interestedTopic);

        auto _it_metrics = _metrics_alerts_map.find(interestedTopic);
        if (_it_metrics != _metrics_alerts_map.end()) {
            _it_metrics->second.push_back(rulename);
        }
        else {
            _metrics_alerts_map.insert(std::make_pair(interestedTopic, std::vector<std::string>{rulename}));
        }
    }

    // put new rule with empty alerts into the cache
    std::vector<PureAlert> emptyAlerts;
    _alerts_map.insert(std::make_pair(rulename, std::make_pair(std::move(temp_rule), emptyAlerts)));

    it = _alerts_map.find(rulename);

    // CURRENT: wait until new measurements arrive
    // TODO: reevaluate immediately ( new Method )
    // reevaluate rule for every known metric
    //  ( requires more sophisticated approach: need to refactor evaluate back
    //  for 2 params + some logic here )

    return 0;
}

int AlertConfiguration::deleteRule(const std::string& name, std::map<std::string, std::vector<PureAlert>>& alertsToSend)
{
    RuleNameMatcher matcher(name);
    std::vector<std::string> dummy;
    return deleteRules(&matcher, alertsToSend, dummy);
}

int AlertConfiguration::deleteAllRules(
    const std::string& element,
    std::map<std::string, std::vector<PureAlert>>& alertsToSend
)
{
    RuleElementMatcher matcher(element);
    std::vector<std::string> dummy;
    return deleteRules(&matcher, alertsToSend, dummy);
}

int AlertConfiguration::deleteRules(
    RuleMatcher* matcher,
    std::map<std::string, std::vector<PureAlert>>& alertsToSend,
    std::vector<std::string>& rulesDeleted
)
{
    // clean up what we can without touching the iterator
    auto rule_to_remove = _alerts_map.begin();
    while (rule_to_remove != _alerts_map.end()) {
        if ((*matcher)(*(rule_to_remove->second.first))) {
            // delete from disk
            int r = rule_to_remove->second.first->remove(getPersistencePath());
            std::string rule_removed_name = rule_to_remove->second.first->name();
            if (r != 0) {
                log_error("Error while removing rule %s", rule_removed_name.c_str());
                return -1;
            }

            // *resolve* found alerts
            for (auto& oneAlert : rule_to_remove->second.second) {
                oneAlert._status = ALERT_RESOLVED;
                oneAlert._description = "Rule deleted";
                // put them into the list of alerts that changed
                alertsToSend[rule_removed_name].push_back(oneAlert);
            }

            for (const auto& interestedTopic : rule_to_remove->second.first->getNeededTopics()) {
                auto _it_metrics = _metrics_alerts_map.find(interestedTopic);
                if (_it_metrics != _metrics_alerts_map.end()) {
                    int it_pos = 0;
                    for (auto& it_rule_in_metric : _it_metrics->second) {
                        if (it_rule_in_metric == rule_removed_name) {
                            _it_metrics->second.erase(_it_metrics->second.begin() + it_pos);
                            break;
                        }
                        it_pos++;
                    }
                }
                else {
                    // should not happened
                    log_error("Remove rule %s with metric %s who was never been add.", rule_removed_name.c_str(),
                        interestedTopic.c_str());
                }
            }
            // clear the cache
            rule_to_remove->second.second.clear();
            rulesDeleted.push_back(rule_removed_name);
            rule_to_remove = _alerts_map.erase(rule_to_remove);
        }
        else {
            ++rule_to_remove;
        }
    }

    return 0;
}

int AlertConfiguration::updateAlert(std::pair<RulePtr, std::vector<PureAlert>>& oneRuleAlerts, const PureAlert& pureAlert, PureAlert& alert_to_send)
{
    bool alertFound{false};

    for (auto& oneAlert : oneRuleAlerts.second) // this object can be changed -> no const
    {
        bool isSameAlert = (pureAlert._element == oneAlert._element);
        if (!isSameAlert) {
            continue;
        }

        // we found the alert
        alertFound = true;

        if (pureAlert._status == ALERT_START) {
            if (oneAlert._status == ALERT_RESOLVED) {
                // Found alert is old. This is new one
                oneAlert._status      = pureAlert._status;
                oneAlert._timestamp   = pureAlert._timestamp;
                oneAlert._description = pureAlert._description;
                oneAlert._severity    = pureAlert._severity;
                oneAlert._actions     = pureAlert._actions;
                // element is the same -> no need to update the field
                log_debug("RULE '%s' : OLD ALERT starts again for element '%s' with description '%s'",
                    oneRuleAlerts.first->name().c_str(), oneAlert._element.c_str(), oneAlert._description.c_str());
            }
            else {
                // Found alert is still active -> it is the same alert
                // If alert is still ongoing, it doesn't mean, that every attribute of alert stayed the same
                oneAlert._description = pureAlert._description;
                oneAlert._severity    = pureAlert._severity;
                oneAlert._actions     = pureAlert._actions;
                log_debug("RULE '%s' : ALERT is ALREADY ongoing for element '%s' with description '%s'",
                    oneRuleAlerts.first->name().c_str(), oneAlert._element.c_str(), oneAlert._description.c_str());
            }

            // in both cases we need to send an alert
            alert_to_send = oneAlert;
            return 0;
        }

        if (pureAlert._status == ALERT_RESOLVED) {
            if (oneAlert._status != ALERT_RESOLVED) {
                // Found alert is not resolved. -> resolve it
                oneAlert._status      = pureAlert._status;
                oneAlert._timestamp   = pureAlert._timestamp;
                oneAlert._description = pureAlert._description;
                oneAlert._severity    = pureAlert._severity;
                oneAlert._actions     = pureAlert._actions;

                log_debug("RULE '%s' : ALERT is resolved for element '%s' with description '%s'",
                    oneRuleAlerts.first->name().c_str(), oneAlert._element.c_str(), oneAlert._description.c_str());

                alert_to_send = oneAlert;
                return 0;
            }
            else {
                // alert was already resolved -> nothing to do
                return -1;
            }
        }

        break; // the alert is processed (alertFound == true)
    } // end of proceesing existing alerts

    if (!alertFound) {
        // this is completly new alert -> need to add it to the list
        // but  only if alert is not resolved
        // IPMVAL-2411 fix: enlarge to RESOLVED status (eg. any known status)
        //             was: if (pureAlert._status != ALERT_RESOLVED)
        if (PureAlert::isStatusKnown(pureAlert._status)) {
            oneRuleAlerts.second.push_back(pureAlert);

            log_debug("RULE '%s' : ALERT is NEW for element '%s' with description '%s'",
                oneRuleAlerts.first->name().c_str(), pureAlert._element.c_str(), pureAlert._description.c_str());

            alert_to_send = PureAlert(pureAlert);
            return 0;
        }
        else {
            // nothing to do, no need to add to the list resolved alerts
            return -1;
        }
    }

    return -1;
}
