/*
 * Copyright (C) 2014 - 2020 Eaton
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*! \file alertconfiguration.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \author Michal Vyskocil  <MichalVyskocil@Eaton.com>
 *  \brief Representation of alert configuration
 */

#pragma once

#include "purealert.h"
#include "rule/rule.h"

#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <vector>

/// Parses the input and reads the rule
///
/// @param[in]  jsonPayload - to parse a rule
/// @param[out] rule - the parsed rule
///
/// @return 1 if rule has errors in json
///         2 if Lua function has errors
///         0 if everything is ok (rule is set)
int readRule(const std::string& jsonPayload, RulePtr& rule);

/// Alert configuration is a class that manages rules and evaruted alerts
///
/// ASSUMPTIONS:
///  1. Rules are stored in files. One rule = one file
///  2. File name is the rule name
///  3. Rule files must have extention ".rule"
///  4. Directory to the files is configurable. Cannot be changed without recompilation
///  5. If rule has at least one mistake or broke any other rule, it is ignored
///  6. Rule name is unique
class AlertConfiguration
{
public:
    typedef typename std::pair<RulePtr, std::vector<PureAlert>> B;
    typedef typename std::unordered_map<std::string, B>         A;
    typedef typename A::value_type                              value_type;
    typedef typename A::iterator                                iterator;

    /// Creates an empty rule-alert configuration
    /// @param[in] path - a directory where rules are stored
    AlertConfiguration(const std::string& path)
        : _path(path) {}

    /// Creates an empty rule-alert configuration with empty path
    AlertConfiguration(): AlertConfiguration("") {}

    /// Reads the configuration from persistence
    /// Set of topics is empty if there are no rules or there are some errors
    /// NOTICE: **Exit** if failed
    /// @return a set of topics to be consumed
    std::set<std::string> readConfiguration();

    /// We need an iterator as a class,
    iterator begin() { return _alerts_map.begin(); }
    iterator end() { return _alerts_map.end(); }
    B& at(const std::string& name) { return _alerts_map.at(name); }
    size_t size() const { return _alerts_map.size(); }
    size_t count(const std::string& name) const { return _alerts_map.count(name); }

    /// Sets a path to configuration files
    /// @param[in] path - a directory where rules are stored
    void setPath(const std::string& path) { _path = path; }
    /// Gets current path to configuration files
    std::string getPersistencePath() const { return _path + '/'; }

    /// Adds a rule to the configuration
    /// alertsToSend must be sent in the order from the first element to the last element
    /// @param[in] newRuleString - json to parse a rule
    /// @param[out] newSubjectsToSubscribe - subjects that are required by the new rule
    /// @param[out] alertsToSend - alerts that where affected by new rule
    /// @param[out] it - iterator to the new rule
    /// @return -1 when rule has error in JSON
    ///         -2 when rule with such name already exists
    ///         -5 when rule has error in Lua
    ///         -6 disk manipulation error (storing, moving...)
    ///          0 when rule was parsed and added correctly (but it can be not saved)
    int addRule(const std::string& newRuleString, std::set<std::string>& newSubjectsToSubscribe,
        std::vector<PureAlert>& alertsToSend, iterator& it);

    /// Updates existing rule in the configuration
    /// alertsToSend must be sent in the order from the first element to the last element
    /// @param[in] newRuleString - json to parse a rule (can have a new name for this rule)
    /// @param[in] rule_name - old name of the rule
    /// @param[out] newSubjectsToSubscribe - subjects that are required by the new rule
    /// @param[out] alertsToSend - alerts that where affected by new rule
    /// @param[out] it - iterator to the new rule
    /// @return -2 when rule with old_name doesn't exist -> nothing to update
    ///         -1 when rule has error in JSON
    ///         -5 when rule has error in Lua
    ///         -3 if name of the rule is changed, but for the new name rule already exists
    ///         -6 disk manipulation error (storing, moving...)
    ///          0 when rule was parsed and updated correctly (but it can be not saved)
    int updateRule(const std::string& newRuleString, const std::string& rule_name, std::set<std::string>& newSubjectsToSubscribe,
        std::vector<PureAlert>& alertsToSend, iterator& it);

    /// Touch existing rule in the configuration.
    /// Indicats that something in rule was changed implicitly.
    /// alertsToSend must be sent in the order from the first element to the last element
    /// @param[in] rule_name - name of the rule to touch
    /// @param[out] alertsToSend - alerts that where affected by this rule
    /// @return -1 when rule with rule_name doesn't exist -> nothing to update
    ///          0 when rule was touched successfully
    int touchRule(const std::string& rule_name, std::vector<PureAlert>& alertsToSend);

    /// Incapsulates alert in the model
    /// @param[in] rule - the evaluated rule
    /// @param[in] pureAlert - the result of the evaluation (alert)
    /// @param[out] alert_to_send - the alert prepared to send
    /// @return -1 nothing to send
    ///          0 need to send an alert
    int updateAlert(std::pair<RulePtr, std::vector<PureAlert>>& it, const PureAlert& pureAlert, PureAlert& alert_to_send);

    /// haveRule (alerts map accessor)
    bool haveRule(const std::string& rule_name) const { return (_alerts_map.find(rule_name) != _alerts_map.end()); }
    bool haveRule(const RulePtr& rule) const { return haveRule(rule->name()); }

    int deleteRule(const std::string& name, std::map<std::string, std::vector<PureAlert>>& alertsToSend);

    int deleteAllRules(const std::string& element, std::map<std::string, std::vector<PureAlert>>& alertsToSend);

    int deleteRules(RuleMatcher* matcher, std::map<std::string, std::vector<PureAlert>>& alertsToSend, std::vector<std::string>& rulesDeleted);

    const std::vector<std::string> getRulesByTopic(const std::string& topic)
    {
        const auto& it = _metrics_alerts_map.find(topic);
        return (it != _metrics_alerts_map.cend()) ? it->second : std::vector<std::string>{};
    }

private:
    // hash map to quickly retrieve specific alert by rulename
    A _alerts_map;

    // map to retrieve alerts that reference a metric
    std::unordered_map<std::string, std::vector<std::string>> _metrics_alerts_map;

    // directory, where rules are stored
    std::string _path;
};
