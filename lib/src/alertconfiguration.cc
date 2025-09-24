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
#include <sstream>

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
            RulePtr tmpRule{newRule}; \
            switch (tmpRule->fill(si)) { \
                case 0: \
                    if (tmpRule->name().empty()) /*secure*/ \
                        { throw std::runtime_error("Rulename is empty"); } \
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

        #undef TRY_RULE_FILL

        // unrecognized rule
        log_error("readRule: rule not recognized");
    }
    catch (const std::exception& e) {
        log_error("readRule: JSON parse error (e: %s)", e.what());
    }

    return 1; // failed (not recognized or internal/json error)
}

// dump (dbg)
std::string AlertConfiguration::str() const
{
    std::ostringstream oss;

    //_alerts_map: std::unordered_map<std::string, std::pair<RulePtr, std::vector<PureAlert>>
    oss << "_alerts_map (size: " << _alerts_map.size() << "):"<< std::endl;
    for (const auto& it : _alerts_map) {
        oss << "+ " << it.second.first->name() << "/" << it.second.first->element() << ": ";
        size_t cnt{0};
        for (const auto& alert : it.second.second) {
            std::string s = alert._element + "/" + alert._status + "/" + alert._severity;
            oss << ((cnt++ == 0) ? "" : ", ") << s;
        }
        oss << std::endl;
    }

    //_metrics_alerts_map: std::unordered_map<std::string, std::vector<std::string>>
    oss << "_metrics_alerts_map (size: " << _metrics_alerts_map.size() << "):" << std::endl;
    for (const auto& it : _metrics_alerts_map) {
        oss << "+ " << it.first << " (size: " << it.second.size() << "): "; // metric/topic
        size_t cnt{0};
        for (const auto& rulename : it.second) {
            oss << ((cnt++ == 0) ? "" : ", ") << rulename;
        }
        oss << std::endl;
    }

    return oss.str();
}

// new/update entry for _metrics_alerts_map
void AlertConfiguration::registerRuleForTopics(const std::vector<std::string>& topics, const std::string& rulename)
{
    for (const auto& topic : topics) {
        const auto& it = _metrics_alerts_map.find(topic);
        if (it != _metrics_alerts_map.end()) { // update
            if (std::find(it->second.begin(), it->second.end(), rulename) == it->second.end()) {
                it->second.push_back(rulename); // unique
            }
        }
        else { // new
            _metrics_alerts_map[topic] = std::vector<std::string>{rulename};
        }
    }
}

// delete entry for _metrics_alerts_map
void AlertConfiguration::unregisterRuleForTopics(const std::vector<std::string>& topics, const std::string& rulename)
{
    for (const auto& topic : topics) {
        const auto& it = _metrics_alerts_map.find(topic);
        if (it != _metrics_alerts_map.end()) {
            // erase rulename from it->second
            it->second.erase(std::remove(it->second.begin(), it->second.end(), rulename), it->second.end());
            if (it->second.empty()) {
                _metrics_alerts_map.erase(it);
            }
        }
    }
}

// set alert to resolved state, update description
void AlertConfiguration::resolveAlert(PureAlert& alert)
{
    alert._status = ALERT_RESOLVED;
    alert._severity = "OK";
}
void AlertConfiguration::resolveAlert(PureAlert& alert, const std::string& description)
{
    resolveAlert(alert);
    alert._description = description;
}

// read persisted rules
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
                    log_warning("'%s' ignored (r: %d)", filename.c_str(), r);
                    continue;
                }
            }

            const std::string rulename{rule->name()};

            // Sanity: rulename and filename must be equal (extension less)
            const std::string filename_noExt{filename.substr(0, filename.find_last_of('.'))};
            if (rulename != filename_noExt) {
                log_warning("'%s' differs from rule name '%s'. Ignored", filename.c_str(), rulename.c_str());
                continue;
            }

            // Sanity: rule must be unique by name
            if (haveRule(rulename)) {
                log_warning("rule '%s' already known. Ignored (file: '%s')", rulename.c_str(), filename.c_str());
                continue;
            }

            // record topics we are interested in
            registerRuleForTopics(rule->getNeededTopics(), rulename);
            // update result
            for (const auto& topic : rule->getNeededTopics())
                { result.insert(topic); }

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
    [[maybe_unused]] std::vector<PureAlert>& alertsToSend,
    AlertConfiguration::iterator& it
)
{
    RulePtr rule{nullptr};
    int r = readRule(jsonPayload, rule);
    if (r != 0) { // failed
        if (r == 2) {
            log_error("nothing created (Lua error, r: %d)", r);
            return -5;
        }
        // r == 1
        log_error("nothing created (unknown or json error, r: %d)", r);
        return -1;
    }

    const std::string rulename{rule->name()};

    if (haveRule(rulename)) {
        log_debug("rule '%s' already exists", rulename.c_str());
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

    // record topics we are interested in
    registerRuleForTopics(rule->getNeededTopics(), rulename);

    // put the rule into the cache (without alerts)
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
    for (auto& alert : it->second.second) {
        resolveAlert(alert, "Rule touched");
        alertsToSend.push_back(alert);
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
    // sanity & need to find out if oldrule exists
    if (oldrulename.empty() || !haveRule(oldrulename)) {
        log_error("rule '%s' doesn't exist", oldrulename.c_str());
        return -2;
    }

    // get the new rule from json
    RulePtr rule{nullptr};
    {
        int r = readRule(jsonPayload, rule);
        if (r != 0) { // failed
            if (r == 2) {
                log_error("nothing created (Lua error, r: %d)", r);
                return -5;
            }
            // r == 1
            log_error("nothing created (unknown or json error, r: %d)", r);
            return -1;
        }
    }

    const std::string rulename{rule->name()};

    // if diff. name, we need to find out if new rule already exists
    if ((rulename != oldrulename) && haveRule(rulename)) {
        log_error("rule '%s' already exists", rulename.c_str());
        return -3;
    }

    // find rule, that should be updated
    auto oldrule = _alerts_map.find(oldrulename);
    if (oldrule == _alerts_map.cend()) {
        // secure, should not happen (see haveRule() above)
        log_error("rule '%s' not found", oldrulename.c_str());
        return -2;
    }

    // handle rule files (old & new)
    {
        // save the rule file
        try {
            rule->save(getPersistencePath(), rulename + ".rule.new");
        }
        catch (const std::exception& e) {
            std::string filename = getPersistencePath() + rulename + ".rule.new";
            log_error("Failed to save file '%s' (e: %s)", filename.c_str(), e.what());
            return -6;
        }
        // remove the oldrule file
        int r = oldrule->second.first->remove(getPersistencePath());
        if (r != 0) {
            log_error("Failed to remove file '%s' (r: %d)", oldrulename.c_str(), r);
            return -6;
        }
        // rename .rule.new as .rule
        const std::string name1{getPersistencePath() + rulename + ".rule.new"};
        const std::string name2{getPersistencePath() + rulename + ".rule"};
        r = std::rename(name1.c_str(), name2.c_str());
        if (r != 0) {
            log_error("Failed to rename '%s' to '%s' (r: %d)", name1.c_str(), name2.c_str(), r);
            return -6;
        }
    }

    // here, everything is done with files
    // and we need to update informations in cache

    // resolve found alerts; put them into the list of alerts that changed
    for (auto& alert : oldrule->second.second) {
        resolveAlert(alert, "Rule updated");
        alertsToSend.push_back(alert);
    }

    // remove oldrule topics we are not interested in
    unregisterRuleForTopics(oldrule->second.first->getNeededTopics(), oldrulename);
    // clear cache & delete oldrule
    oldrule->second.second.clear();
    oldrule->second.first.reset();
    _alerts_map.erase(oldrule);

    // record rule topics we are interested in
    registerRuleForTopics(rule->getNeededTopics(), rulename);

    // put the rule into the cache (without alerts)
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
    // match on rule element?
    auto pElementMatcher = dynamic_cast<const RuleElementMatcher*>(&matcher);

    const std::string description{"Rule deleted"}; // descr. for resolved alerts

    // clean up what we can without touching the iterator
    size_t errCnt{0};
    auto it = _alerts_map.begin();
    while (it != _alerts_map.end()) {
        const std::string rulename{it->second.first->name()};

        if (matcher.match(it->second.first)) {
            // delete rule from disk
            int r = it->second.first->remove(getPersistencePath());
            if (r != 0) {
                log_error("Failed to remove file for rule %s", rulename.c_str());
                errCnt++;
                ++it;
                continue;
            }

            // *resolve* rule alerts
            // put them in the list of alerts that have changed
            for (auto& alert : it->second.second) {
                resolveAlert(alert, description);
                alertsToSend[rulename].push_back(alert);
            }

            // remove topics we are not interested in
            unregisterRuleForTopics(it->second.first->getNeededTopics(), rulename);

            // clear cache & delete the rule
            it->second.second.clear();
            it->second.first.reset();
            it = _alerts_map.erase(it);

            rulesDeleted.push_back(rulename);
        }
        else {
            if ((rulename == "warranty") && pElementMatcher) {
                // warranty rule exception on delete-element
                // iterate to resolve & erase alert that reference element
                bool first{true};
                for (auto it_alert = it->second.second.begin(); it_alert != it->second.second.end();) {
                    if (pElementMatcher->element() == it_alert->_element) {
                        resolveAlert(*it_alert, description);
                        alertsToSend[rulename].push_back(*it_alert);
                        // delete alert
                        it_alert = it->second.second.erase(it_alert);
                        if (first) {
                            rulesDeleted.push_back(rulename + "@" + pElementMatcher->element());
                            first = false; // once
                        }
                    }
                    else {
                        ++it_alert;
                    }
                }
            }

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
        if (oneAlert._element != pureAlert._element) {
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
            // else {} // nop (alert is resolved)
        }

        return ret; // alert found & processed
    }

    // here, this is a new alert
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
    // else {} // nop

    return ret;
}
