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

#include "rule/thresholdrulesimple.h"
#include "rule/thresholdrulecomplex.h"
#include "rule/normalrule.h"
#include "rule/regexrule.h"

#include "misc/utils.h"

#include <fty_log.h>
#include <fty_common_json.h>
#include <cxxtools/serializationinfo.h>
#include <czmq.h>
#include <algorithm>
#include <filesystem>

// returns 0 if ok, else error (1: not recognized, 2: bad Lua)
int readRule(const std::string& jsonPayload, RulePtr& rule)
{
    rule.reset();

    // TODO check, that rule actions have unique names (in the rule)
    // TODO check, that values have unique name (in the rule)
    try {
        // json w/ unique member
        cxxtools::SerializationInfo si;
        JSON::readFromString(jsonPayload, si);
        if (si.memberCount() != 1)
            { throw std::runtime_error("Unique member expected"); }

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
                    logDebug("readRule: recognize rule '{}' ({})", rule->name(), rule->clazz()); \
                    return 0; \
                case 2: /*Lua error*/ \
                    return 2; \
                default:; \
            } \
        }

        TRY_RULE_FILL(new ThresholdRuleSimple());
        TRY_RULE_FILL(new ThresholdRuleComplex());
        TRY_RULE_FILL(new NormalRule());
        TRY_RULE_FILL(new RegexRule());

        // unrecognized rule
        log_error("readRule: rule not recognized");
    }
    catch (const std::exception& e) {
        log_error("readRule: JSON parse error (e: %s)", e.what());
    }

    return 1; // failed (unrecognized or internal/json error)
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

            const std::string filename{fn.path().filename()};

            // read rule from the file
            RulePtr rule{nullptr};
            {
                log_debug("processing file: '%s'", fn.path().c_str());
                const std::string json{utils::readFile(fn.path())};
                int r = readRule(json, rule);
                if (r != 0) { // rule can't be read/recognized
                    log_warning("'%s' ignored (r = %d)", filename.c_str(), r);
                    continue;
                }
            }

            const std::string rulename{rule->name()};

            // Sanity: rulename and filename must be equal (extension less)
            const std::string filename_noext{filename.substr(0, filename.find_last_of('.'))};
            if (rulename != filename_noext) {
                log_warning("'%s' differs from rule name '%s'. Ignored", filename.c_str(), rulename.c_str());
                continue;
            }

            // Sanity: rule must be unique by name
            if (haveRule(rulename)) {
                log_warning("rule '%s' already known. Ignored (file: '%s')", rulename.c_str(), filename.c_str());
                continue;
            }

            // record topics we are interested in
            for (const auto& topic : rule->getNeededTopics()) {
                result.insert(topic);

                const auto& it_m = _metrics_alerts_map.find(topic);
                if (it_m != _metrics_alerts_map.end()) {
                    it_m->second.push_back(rulename);
                }
                else {
                    _metrics_alerts_map[topic] = std::vector<std::string>{rulename};
                }
            }

            // add rule to the configuration (without alert)
            _alerts_map[rulename] = std::make_pair(std::move(rule), std::vector<PureAlert>{});

            log_debug("file '%s' read correctly", filename.c_str());
        }
    }
    catch (const std::exception& e) {
        log_fatal("EXIT_FAILURE - Can't read %s configuration (e: %s)", _path.c_str(), e.what());
        exit(EXIT_FAILURE); // ZZZ EXIT
    }

    return result;
}

int AlertConfiguration::addRule(
    const std::string& jsonPayload,
    std::vector<PureAlert>& /* alertsToSend */,
    AlertConfiguration::iterator& it
)
{
    RulePtr rule{nullptr};
    int r = readRule(jsonPayload, rule);
    if (r != 0) { // failed
        switch (r) {
            case 1:
                log_error("nothing created (unrecognized rule or json error, r: %d)", r);
                return -1;
            case 2:
                log_error("nothing created (Lua error, r: %d)", r);
                return -5;
            default:;
        }
        log_error("nothing created (r: %d)", r);
        return -1;
    }

    const std::string rulename{rule->name()};

    if (haveRule(rulename)) {
        log_debug("rule %s already exists", rulename.c_str());
        return -2;
    }

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

    try {
        rule->save(getPersistencePath(), rulename + ".rule");
    }
    catch (const std::exception& e) {
        const std::string filename{getPersistencePath() + rulename + ".rule"};
        log_error("Error saving file '%s' (e: %s)", filename.c_str(), e.what());
        return -6;
    }

    // handle new topics
    for (const auto& topic : rule->getNeededTopics()) {
        //log_debug("topic:", topic.c_str());
        const auto& it_m = _metrics_alerts_map.find(topic);
        if (it_m != _metrics_alerts_map.end()) {
            log_debug("_metrics_alerts_map: new rule %s for topic %s ", rulename.c_str(), topic.c_str());
            it_m->second.push_back(rulename);
        }
        else {
            log_debug("_metrics_alerts_map: new topic %s for rule %s ", topic.c_str(), rulename.c_str());
            _metrics_alerts_map[topic] = std::vector<std::string>{rulename};
        }
    }

    // put the rule without alerts into the cache
    _alerts_map[rulename] = std::make_pair(std::move(rule), std::vector<PureAlert>{});

    it = _alerts_map.find(rulename);

    return 0;
}

int AlertConfiguration::touchRule(const std::string& rulename, std::vector<PureAlert>& alertsToSend)
{
    // find rule, that should be touched
    const auto& it = _alerts_map.find(rulename);
    if (it == _alerts_map.end()) {
        log_error("rule '%s' doesn't exist", rulename.c_str());
        return -1;
    }

    // resolve alerts to send
    for (auto& oneAlert : it->second.second) {
        oneAlert._status = ALERT_RESOLVED;
        oneAlert._description = "Rule touched";
        alertsToSend.push_back(oneAlert);
    }

    // finally, clear alerts cache
    it->second.second.clear();

    return 0;
}

int AlertConfiguration::updateRule(
    const std::string& jsonPayload, // json
    const std::string& oldrulename, // rule to update
    std::vector<PureAlert>& alertsToSend,
    AlertConfiguration::iterator& it
)
{
    // need to find out if rule exists already or not
    if (oldrulename.empty()) {
        log_error("rule oldrulename is empty");
        return -2;
    }
    if (!haveRule(oldrulename)) {
        log_error("rule '%s' doesn't exist", oldrulename.c_str());
        return -2;
    }

    RulePtr rule{nullptr};
    {
        int r = readRule(jsonPayload, rule);
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
    }

    const std::string rulename{rule->name()};

    // if name of the rule changed, then
    // need to find out if rule with new rulename exists already or not
    if ((rulename != oldrulename) && haveRule(rulename)) {
        // rule with new oldrulename
        log_error("Rule with such name already exists");
        return -3;
    }

    // find rule, that should be updated
    auto rule_to_update = _alerts_map.find(oldrulename);
    if (rule_to_update == _alerts_map.cend()) {
        // secure, should not happen (see haveRule() above)
        log_error("rule '%s' not found", oldrulename.c_str());
        return -2;
    }

    const std::string rule_removed_name{rule_to_update->second.first->name()};

    // handle rule file (old & new)
    {
        // first, save the file (new)
        try {
            rule->save(getPersistencePath(), rulename + ".rule.new");
        }
        catch (const std::exception& e) {
            // if error happend, we didn't lose any previous data
            std::string filename = getPersistencePath() + rulename + ".rule.new";
            log_error("Error while saving file '%s': %s", filename.c_str(), e.what());
            return -6;
        }

        // remove the old file
        int r = rule_to_update->second.first->remove(getPersistencePath());
        if (r != 0) {
            log_error(
                "Old rule wasn't removed, but new one stored with postfix '.new' and is not used yet. Rename *.rule.new "
                "file to *.rule, remove old .rule and then manually and restart the daemon",
                rule_removed_name.c_str());
            return -6;
        }

        // rename new rule file to the right name
        const std::string name1{getPersistencePath() + rule_removed_name + ".rule.new"};
        const std::string name2{getPersistencePath() + rule_removed_name + ".rule"};
        r = std::rename(name1.c_str(), name2.c_str());
        if (r != 0) {
            log_error(
                "Error renaming .rule.new to .new for '%s'. Rename *.rule.new file to *.rule and then manually and restart the daemon",
                rule_removed_name.c_str());
            return -6;
        }
    }

    // here, everything is done with files
    // and we need to update informations in the memory cache

    // resolve found alerts; put them into the list of alerts that changed
    for (auto& oneAlert : rule_to_update->second.second) {
        oneAlert._status = ALERT_RESOLVED;
        alertsToSend.push_back(oneAlert);
    }

    for (const auto& topic : rule_to_update->second.first->getNeededTopics()) {
        const auto& it_m = _metrics_alerts_map.find(topic);
        if (it_m != _metrics_alerts_map.end()) {
            int it_pos = 0;
            for (const auto& it_rulename : it_m->second) {
                if (it_rulename == rule_removed_name) {
                    it_m->second.erase(it_m->second.begin() + it_pos);
                    break;
                }
                it_pos++;
            }
        }
        else { // should not happen
            log_error("Remove rule %s with metric %s who was never been add.",
                rule_removed_name.c_str(), topic.c_str());
        }
    }

    // clear cache & delete old rule
    rule_to_update->second.second.clear();
    rule_to_update->second.first.reset();
    // remove entire entry
    _alerts_map.erase(rule_to_update);

    // handle new topics
    for (const auto& topic : rule->getNeededTopics()) {
        const auto& it_m = _metrics_alerts_map.find(topic);
        if (it_m != _metrics_alerts_map.end()) {
            it_m->second.push_back(rulename);
        }
        else {
            _metrics_alerts_map[topic] = std::vector<std::string>{rulename};
        }
    }

    // put the rule without alerts into the cache
    _alerts_map[rulename] = std::make_pair(std::move(rule), std::vector<PureAlert>{});

    it = _alerts_map.find(rulename);

    return 0;
}

int AlertConfiguration::deleteRules(
    const RuleMatcher& matcher,
    std::map<std::string, std::vector<PureAlert>>& alertsToSend,
    std::vector<std::string>& rulesDeleted
)
{
    size_t errCnt{0};

    // clean up what we can without touching the iterator
    auto it = _alerts_map.begin();
    while (it != _alerts_map.end()) {
        if (matcher.match(it->second.first)) {
            const std::string rule_removed{it->second.first->name()};

            // delete from disk
            int r = it->second.first->remove(getPersistencePath());
            if (r != 0) {
                log_error("Error while removing rule %s", rule_removed.c_str());
                errCnt++;
                continue;
            }

            // *resolve* rule alerts
            // put them in the list of alerts that have changed
            for (auto& alert : it->second.second) {
                alert._status = ALERT_RESOLVED;
                alert._description = "Rule deleted";
                alertsToSend[rule_removed].push_back(alert);
            }

            // update _metrics_alerts_map
            for (const auto& topic : it->second.first->getNeededTopics()) {
                const auto& it_m = _metrics_alerts_map.find(topic);
                if (it_m != _metrics_alerts_map.end()) {
                    int it_pos = 0;
                    for (const auto& it_rulename : it_m->second) {
                        if (it_rulename == rule_removed) {
                            it_m->second.erase(it_m->second.begin() + it_pos);
                            break;
                        }
                        it_pos++;
                    }
                }
                else { // should not happen
                    log_error("Remove rule %s with metric %s who was never been add.", rule_removed.c_str(), topic.c_str());
                }
            }

            // clear Alert cache
            it->second.second.clear();
            // finally delete the rule
            it = _alerts_map.erase(it);

            rulesDeleted.push_back(rule_removed);
        }
        else {
            ++it;
        }
    }

    return (errCnt == 0) ? 0 : -1;
}

int AlertConfiguration::updateAlert(std::pair<RulePtr, std::vector<PureAlert>>& oneRuleAlerts, const PureAlert& pureAlert, PureAlert& alertToSend)
{
    int ret{-1}; // nop, alertToSend not set

    for (auto& oneAlert : oneRuleAlerts.second) // oneAlert can be changed (no const)
    {
        if (pureAlert._element != oneAlert._element) {
            continue; // does not apply
        }

        // we found the alert

        if (pureAlert._status == ALERT_START) {
            if (oneAlert._status == ALERT_RESOLVED) {
                // Found alert is old. This is new one
                oneAlert._status      = pureAlert._status;
                oneAlert._timestamp   = pureAlert._timestamp;
                oneAlert._description = pureAlert._description;
                oneAlert._severity    = pureAlert._severity;
                oneAlert._actions     = pureAlert._actions;

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
            alertToSend = oneAlert;
            ret = 0;
        }
        else if (pureAlert._status == ALERT_RESOLVED) {
            if (oneAlert._status != ALERT_RESOLVED) {
                // Found alert is not resolved. -> resolve it
                oneAlert._status      = pureAlert._status;
                oneAlert._timestamp   = pureAlert._timestamp;
                oneAlert._description = pureAlert._description;
                oneAlert._severity    = pureAlert._severity;
                oneAlert._actions     = pureAlert._actions;

                log_debug("RULE '%s' : ALERT is resolved for element '%s' with description '%s'",
                    oneRuleAlerts.first->name().c_str(), oneAlert._element.c_str(), oneAlert._description.c_str());

                alertToSend = oneAlert;
                ret = 0;
            }
            // else {} // nothing to do, the alert was already resolved
        }

        return ret; // the alert was found & processed
    }

    // here, this is completly a new alert
    // we need to add it to the list, but *only* if alert is not resolved
    // IPMVAL-2411 fix: enlarge to RESOLVED status (eg. any known status)
    //             was: if (pureAlert._status != ALERT_RESOLVED)
    if (PureAlert::isStatusKnown(pureAlert._status)) {
        oneRuleAlerts.second.push_back(pureAlert);

        log_debug("RULE '%s' : ALERT is NEW for element '%s' with description '%s'",
            oneRuleAlerts.first->name().c_str(), pureAlert._element.c_str(), pureAlert._description.c_str());

        alertToSend = PureAlert(pureAlert);
        ret = 0;
    }
    // else {} // nothing to do

    return ret;
}
