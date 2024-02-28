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
#include "normalrule.h"
#include "regexrule.h"
#include "thresholdrulecomplex.h"
#include "thresholdruledevice.h"
#include "thresholdrulesimple.h"
#include <algorithm>
#include <czmq.h>
#include <filesystem>
#include <fty_common_json.h>
#include <cxxtools/serializationinfo.h>

int readRule(std::istream& f, RulePtr& rule)
{
    rule.reset();
    // TODO check, that rule actions have unique names (in the rule)
    // TODO check, that values have unique name (in the rule)
    try {
        cxxtools::SerializationInfo si2;
        {
            std::string json_string(std::istreambuf_iterator<char>(f), {});
            JSON::readFromString(json_string, si2);
            if (si2.memberCount() == 0)
                throw std::runtime_error("empty input json document");
        }

        // MVY: SerializationInfo can contain more items, which is not what we
        //     want, pick the first one
        cxxtools::SerializationInfo si;
        si.addMember(si2.getMember(0).name()) <<= si2.getMember(0);

        std::unique_ptr<Rule> temp_rule;

        {
            temp_rule = std::unique_ptr<Rule>{new RegexRule()};
            int rv    = temp_rule->fill(si);
            if (rv == 0) {
                rule = std::move(temp_rule);
                return 0;
            }
            if (rv == 2)
                return 2;
        }

        {
            temp_rule = std::unique_ptr<Rule>{new ThresholdRuleSimple()};
            int rv    = temp_rule->fill(si);
            if (rv == 0) {
                rule = std::move(temp_rule);
                return 0;
            }
            if (rv == 2)
                return 2;
        }

        {
            temp_rule = std::unique_ptr<Rule>{new ThresholdRuleDevice()};
            int rv    = temp_rule->fill(si);
            if (rv == 0) {
                rule = std::move(temp_rule);
                return 0;
            }
            if (rv == 2)
                return 2;
        }

        {
            temp_rule = std::unique_ptr<Rule>{new ThresholdRuleComplex()};
            int rv    = temp_rule->fill(si);
            if (rv == 0) {
                rule = std::move(temp_rule);
                return 0;
            }
            if (rv == 2)
                return 2;
        }

        {
            temp_rule = std::unique_ptr<Rule>{new NormalRule()};
            int rv    = temp_rule->fill(si);
            if (rv == 0) {
                rule = std::move(temp_rule);
                return 0;
            }
            if (rv == 2)
                return 2;
        }
        log_error("Cannot detect type of the rule");
        return 1;
    } catch (const std::exception& e) {
        log_error("Cannot parse JSON, ignore it. %s", e.what());
        return 1;
    }
}

std::set<std::string> AlertConfiguration::readConfiguration(void)
{
    // list of topics, that are needed to be consumed for rules
    std::set<std::string> result;

    log_debug("read rules files from '%s'", _path.c_str());

    try {
        if (!std::filesystem::exists(_path)) {
            std::filesystem::create_directories(_path);
        }
        std::filesystem::path d(_path);
        // every rule at the beggining has empty set of alerts
        std::vector<PureAlert> emptyAlerts{};
        for (const auto& fn : std::filesystem::directory_iterator(d)) {

            // we are interested only in files with names "*.rule"
            if (fn.path().extension() != ".rule") {
                continue;
            }

            // read rule from the file
            std::ifstream f(fn.path());
            log_debug("processing_file: '%s'", fn.path().native().c_str());
            std::unique_ptr<Rule> rule;
            int                   rv = readRule(f, rule);
            if (rv != 0) {
                // rule can't be read correctly from the file
                log_warning("nothing to do");
                continue;
            }

            std::string fname = fn.path().filename();
            // ASSUMPTION: name of the file is the same as name of the rule
            // If they are different ignore this rule
            if (!rule->hasSameNameAs(fname.substr(0, fname.length() - 5))) {
                log_warning(
                    "file name '%s' differs from rule name '%s', ignore it", fname.c_str(), rule->name().c_str());
                continue;
            }

            // ASSUMPTION: rules have unique names
            if (haveRule(rule)) {
                log_warning("rule with name '%s' already known, ignore this one. File '%s'", rule->name().c_str(),
                    fname.c_str());
                continue;
            }
            std::string rulename = rule->name();
            // record topics we are interested in
            for (const auto& interestedTopic : rule->getNeededTopics()) {
                result.insert(interestedTopic);
                auto _it_metrics = _metrics_alerts_map.find(interestedTopic);
                if (_it_metrics != _metrics_alerts_map.end()) {
                    _it_metrics->second.push_back(rulename);
                } else {
                    _metrics_alerts_map.insert(std::make_pair(interestedTopic, std::vector<std::string>{rulename}));
                }
            }

            // add rule to the configuration
            _alerts_map.insert(std::make_pair(rulename, std::make_pair(std::move(rule), emptyAlerts)));
            log_debug("file '%s' read correctly", fname.c_str());
        }
    } catch (std::exception& e) {
        log_error("Can't read configuration: %s", e.what());
        exit(1);
    }
    return result;
}

int AlertConfiguration::addRule(std::istream& newRuleString, std::set<std::string>& newSubjectsToSubscribe,
    std::vector<PureAlert>& /* alertsToSend */, AlertConfiguration::iterator&       it)
{
    // ASSUMPTIONS: newSubjectsToSubscribe is empty
    if (!newSubjectsToSubscribe.empty()) {
        log_debug("ERROR ASSUMPTION: newSubjectsToSubscribe is empty");
        newSubjectsToSubscribe.clear();
    }

    RulePtr temp_rule;
    int     rv = readRule(newRuleString, temp_rule);
    if (rv == 1) {
        log_error("nothing created, json error");
        return -1;
    }
    if (rv == 2) {
        log_error("nothing created, lua error");
        return -5;
    }

    // PQSWMBT-3723, don't instanciate sensor temp./humidity rules directly
    if ((temp_rule->name().find("humidity.default@sensor-") == 0) // starts with...
        || (temp_rule->name().find("temperature.default@sensor-") == 0)) {
        log_debug("rule instanciation rejected (%s)", temp_rule->name().c_str());
        return -100;
    }
    // end PQSWMBT-3723

    // PQSWMBT-4921 Xphase rule exceptions (see templateruleconfigurator.cc)
    auto asset = temp_rule->name().substr(temp_rule->name().find("@") + 1);
    if (!ruleXphaseIsApplicable(temp_rule->name(), getAssetInfoFromAutoconfig(asset))) {
        log_debug("Xphase rule instanciation rejected (%s)", temp_rule->name().c_str());
        return -101;
    }
    // end PQSWMBT-4921

    log_debug("addRule %s", temp_rule->name().c_str());

    if ( haveRule (temp_rule) ) {
        log_error ("rule already exists");
        return -2;
    }

    try {
        temp_rule->save(getPersistencePath(), temp_rule->name() + ".rule");
    } catch (const std::exception& e) {
        log_error("Error saving file '%s': %s",
            (getPersistencePath() + temp_rule->name() + ".rule").c_str(),
            e.what());
        return -6;
    }

    std::string rulename = temp_rule->name();
    // in any case we need to check new subjects
    for (const auto& interestedTopic : temp_rule->getNeededTopics()) {
        //log_debug("interestedTopic:", interestedTopic.c_str());
        newSubjectsToSubscribe.insert(interestedTopic);
        auto _it_metrics = _metrics_alerts_map.find(interestedTopic);
        if (_it_metrics != _metrics_alerts_map.end()) {
            log_debug("_it_metrics %s: add rule %s ", _it_metrics->first.c_str(), rulename.c_str());
            _it_metrics->second.push_back(rulename);
        } else {
            log_debug("_metrics_alerts_map insert: topic: %s, rule %s ", interestedTopic.c_str(), rulename.c_str());
            _metrics_alerts_map.insert(std::make_pair(interestedTopic, std::vector<std::string>{rulename}));
        }
    }

    std::vector<PureAlert> emptyAlerts{};
    _alerts_map.insert(std::make_pair(rulename, std::make_pair(std::move(temp_rule), emptyAlerts)));
    it = _alerts_map.find(rulename);

    return 0;
}

int AlertConfiguration::touchRule(const std::string& rule_name, std::vector<PureAlert>& alertsToSend)
{
    // find rule, that should be touched
    auto rule_to_update = _alerts_map.find(rule_name);
    // rule_to_update is an iterator to the rule+alerts
    if (rule_to_update == _alerts_map.end()) {
        log_error("rule '%s' doesn't exist", rule_name.c_str());
        return -1;
    }

    // resolve found alerts
    for (auto& oneAlert : rule_to_update->second.second) {
        oneAlert._status      = ALERT_RESOLVED;
        oneAlert._description = "Rule was changed implicitly";
        // put them into the list of alerts that had changed
        alertsToSend.push_back(oneAlert);
    }
    // clear alert cache
    rule_to_update->second.second.clear();

    return 0;
}

int AlertConfiguration::updateRule(std::istream& newRuleString, const std::string& old_name,
    std::set<std::string>& newSubjectsToSubscribe, std::vector<PureAlert>& alertsToSend,
    AlertConfiguration::iterator& it)
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
    if (!haveRule(old_name)) {
        log_error("rule doesn't exist");
        return -2;
    }

    RulePtr temp_rule;
    int     rv = readRule(newRuleString, temp_rule);
    if (rv == 1) {
        log_error("nothing to update, json error");
        return -1;
    }
    if (rv == 2) {
        log_error("nothing to update, lua error");
        return -5;
    }
    // if name of the rule changed, then
    // need to find out if rule with new rulename exists already or not
    if (!temp_rule->hasSameNameAs(old_name) && haveRule(temp_rule->name())) {
        // rule with new old_name
        log_error("Rule with such name already exists");
        return -3;
    }

    // find rule, that should be updated
    auto rule_to_update = _alerts_map.find(old_name);

    // try to save the file, first
    try {
        temp_rule->save(getPersistencePath(), temp_rule->name() + ".rule.new");
    } catch (const std::exception& e) {
        // if error happend, we didn't lose any previous data
        log_error("Error while saving file '%s': %s", (getPersistencePath() + temp_rule->name() + ".rule.new").c_str(),
            e.what());
        return -6;
    }
    // as we successfuly saved the new file, we can try to remove old one
    rv                            = rule_to_update->second.first->remove(getPersistencePath());
    std::string rule_removed_name = rule_to_update->second.first->name();
    if (rv != 0) {
        log_error(
            "Old rule wasn't removed, but new one stored with postfix '.new' and is not used yet. Rename *.rule.new "
            "file to *.rule, remove old .rule and then manually and restart the daemon",
            rule_removed_name.c_str());
        return -6;
    }
    // as we successfuly removed old rule, we can rename new rule to the right name
    rv = std::rename(getPersistencePath().append(rule_removed_name).append(".rule.new").c_str(),
        getPersistencePath().append(rule_removed_name).append(".rule").c_str());
    if (rv != 0) {
        log_error(
            "Error renaming .rule.new to .new for '%s'. Rename *.rule.new file to *.rule and then manually and restart "
            "the daemon",
            rule_removed_name.c_str());
        return -6;
    }
    // so, in the files now everything ok
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
        } else {
            // should not happened
            log_error("Remove rule %s with metric %s who was never been add.", rule_removed_name.c_str(),
                interestedTopic.c_str());
        }
    }
    // clear cache
    rule_to_update->second.second.clear();
    // remove old rule
    rule_to_update->second.first.reset();
    // remove entire entiry
    _alerts_map.erase(rule_to_update);

    // find new topics to subscribe
    std::vector<PureAlert> emptyAlerts{};
    std::string            rulename = temp_rule->name();
    // As we changed the rule, we need to check new subjects
    for (const auto& interestedTopic : temp_rule->getNeededTopics()) {
        newSubjectsToSubscribe.insert(interestedTopic);
        auto _it_metrics = _metrics_alerts_map.find(interestedTopic);
        if (_it_metrics != _metrics_alerts_map.end()) {
            _it_metrics->second.push_back(rulename);
        } else {
            _metrics_alerts_map.insert(std::make_pair(interestedTopic, std::vector<std::string>{rulename}));
        }
    }
    // put new rule with empty alerts into the cache
    _alerts_map.insert(std::make_pair(rulename, std::make_pair(std::move(temp_rule), emptyAlerts)));
    it = _alerts_map.find(rulename);
    // CURRENT: wait until new measurements arrive
    // TODO: reevaluate immidiately ( new Method )
    // reevaluate rule for every known metric
    //  ( requires more sophisticated approach: need to refactor evaluate back
    //  for 2 params + some logic here )
    return 0;
}

int AlertConfiguration::deleteRule(const std::string& name, std::map<std::string, std::vector<PureAlert>>& alertsToSend)
{
    RuleNameMatcher          matcher(name);
    std::vector<std::string> dummy;
    return deleteRules(&matcher, alertsToSend, dummy);
}

int AlertConfiguration::deleteAllRules(
    const std::string& element, std::map<std::string, std::vector<PureAlert>>& alertsToSend)
{
    RuleElementMatcher       matcher(element);
    std::vector<std::string> dummy;
    return deleteRules(&matcher, alertsToSend, dummy);
}

int AlertConfiguration::deleteRules(RuleMatcher* matcher, std::map<std::string, std::vector<PureAlert>>& alertsToSend,
    std::vector<std::string>& rulesDeleted)
{
    // clean up what we can without touching the iterator
    auto rule_to_remove = _alerts_map.begin();
    while (rule_to_remove != _alerts_map.end()) {
        if ((*matcher)(*(rule_to_remove->second.first))) {
            // delete from disk
            int         rv                = rule_to_remove->second.first->remove(getPersistencePath());
            std::string rule_removed_name = rule_to_remove->second.first->name();
            if (rv != 0) {
                log_error("Error while removing rule %s", rule_removed_name.c_str());
                return -1;
            }
            // resolve found alerts
            for (auto& oneAlert : rule_to_remove->second.second) {
                oneAlert._status      = ALERT_RESOLVED;
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
                } else {
                    // should not happened
                    log_error("Remove rule %s with metric %s who was never been add.", rule_removed_name.c_str(),
                        interestedTopic.c_str());
                }
            }
            // clear the cache
            rule_to_remove->second.second.clear();
            rulesDeleted.push_back(rule_removed_name);
            rule_to_remove = _alerts_map.erase(rule_to_remove);
        } else {
            ++rule_to_remove;
        }
    }

    // delete rules from memory
    //    auto new_end = std::remove_if (_alerts.begin (),
    //                                   _alerts.end (),
    //                                    [matcher] (std::pair < RulePtr, std::vector<PureAlert> > const &alert) {
    //                                        return (*matcher)(*(alert.first));
    //                                    });
    //    _alerts.erase (new_end, _alerts.end ());
    return 0;
}

int AlertConfiguration::updateAlert(std::pair<RulePtr, std::vector<PureAlert>>& oneRuleAlerts,
    /*const RulePtr &rule,*/
    const PureAlert& pureAlert, PureAlert& alert_to_send)
{
    // we found the rule
    bool isAlertFound = false;
    for (auto& oneAlert : oneRuleAlerts.second) // this object can be changed -> no const
    {
        bool isSameAlert = (pureAlert._element == oneAlert._element);
        if (!isSameAlert) {
            continue;
        }
        // we found the alert
        isAlertFound = true;
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
            } else {
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
            // alert_to_send = PureAlert(oneAlert);
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
                // alert_to_send = PureAlert(oneAlert);
                return 0;
            } else {
                // alert was already resolved -> nothing to do
                return -1;
            }
        }
    } // end of proceesing existing alerts

    if (!isAlertFound) {
        // this is completly new alert -> need to add it to the list
        // but  only if alert is not resolved
        // IPMVAL-2411 fix: enlarge to RESOLVED status (eg. any known status)
        //             was: if (pureAlert._status != ALERT_RESOLVED)
        if (PureAlert::isStatusKnown(pureAlert._status.c_str())) {
            oneRuleAlerts.second.push_back(pureAlert);
            log_debug("RULE '%s' : ALERT is NEW for element '%s' with description '%s'",
                oneRuleAlerts.first->name().c_str(), pureAlert._element.c_str(), pureAlert._description.c_str());
            alert_to_send = PureAlert(pureAlert);
            return 0;
        } else {
            // nothing to do, no need to add to the list resolved alerts
            return -1;
        }
    } else {
        return -1;
    }
    //    } // end of processing one rule
    return -1;
}


int AlertConfiguration::updateAlertState(
    const char* rule_name, const char* element_name, const char* new_state, PureAlert& pureAlert)
{
    if (!PureAlert::isStatusKnown(new_state)) {
        log_error("Unknown new status, ignore it");
        return -5;
    }
    if (strcmp(new_state, ALERT_RESOLVED) == 0) {
        log_error("User can't resolve alert manually");
        return -2;
    }
    auto oneRuleAlerts = _alerts_map.find(rule_name);
    if (oneRuleAlerts != _alerts_map.end()) {
        // we found the rule
        for (auto& oneAlert : oneRuleAlerts->second.second) {
            bool isSameAlert = (oneAlert._element == element_name);
            if (!isSameAlert) {
                continue;
            }
            // we found the alert
            if (oneAlert._status == ALERT_RESOLVED) {
                log_error("Alert %s with rule %s : RESOLVED alert cannot be changed manually",
                    oneAlert._element.c_str(), oneAlert._rule_class.c_str());
                return -1;
            }
            oneAlert._status = new_state;
            pureAlert        = oneAlert;
            return 0;
        }
    }
    log_error("Cannot acknowledge alert, because it doesn't exist");
    return -4;
}
