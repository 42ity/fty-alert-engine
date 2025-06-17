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

/// @file rule.h
/// @author Alena Chernikava <AlenaChernikava@Eaton.com>
/// @brief General representation of rule

#pragma once

#include "purealert.h"
#include "metric/metriclist.h"

#include <fty_log.h>
#include <fty_common_json.h>
#include <cxxtools/serializationinfo.h>

#include <czmq.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <set>
#include <map>
#include <string>
#include <vector>

void si_getValueUtf8(const cxxtools::SerializationInfo& si, const std::string& member_name, std::string& result);

/// Helper structure to store a possible outcome of rule evaluation
///
/// Rule evaluation outcome has three values:
/// - actions
/// - severity // severity is detected automatically !!!! user cannot change it
/// - description
struct Outcome
{
    std::vector<std::string> _actions;
    std::string              _severity;
    std::string              _description;

    std::string str() //dump DBG
    {
        std::ostringstream oss;

        int i = 0;
        for (auto& a : _actions) {
            oss << "actions[" << i << "](" << a << "),";
            i++;
        }
        oss << "severity(" << _severity << "),"
            << "description(" << _description << ")";

        return oss.str();
    }
};

enum RULE_RESULT
{
    RULE_RESULT_LOW_CRITICAL  = -2,
    RULE_RESULT_LOW_WARNING   = -1,
    RULE_RESULT_OK            = 0,
    RULE_RESULT_HIGH_WARNING  = 1,
    RULE_RESULT_HIGH_CRITICAL = 2,
    RULE_RESULT_UNKNOWN       = 3,
};

/// Deserialzation of outcome
void operator >>= (const cxxtools::SerializationInfo& si, Outcome& outcome);
void operator >>= (const cxxtools::SerializationInfo& si, std::map<std::string, Outcome>& outcomes);

/// Values
void operator >>= (const cxxtools::SerializationInfo& si, std::map<std::string, double>& values);

class Rule;
using RulePtr = std::unique_ptr<Rule>;

/// General representation for rules
class Rule
{
public: // virtual methods
    virtual ~Rule() {}
    virtual std::string whoami() const { return ""; }
    virtual int fill(const cxxtools::SerializationInfo& si) = 0;
    virtual void globalVariables(const std::map<std::string, double>& vars)
    {
        _variables = vars;
    }

    /// get/set code
    virtual void code(const std::string& /* code */)
    {
        throw std::runtime_error("Method not supported by this type of rule");
    }
    virtual std::string code() const
    {
        throw std::runtime_error("Method not supported by this type of rule");
    }

    /// Evaluates the rule
    /// @param[in] metricList - a list of known metrics
    /// @param[out] pureAlert - result of evaluation
    /// @return 0 if evaluation was correct
    ///         non 0 if there were some errors during the evaluation
    virtual int evaluate(const MetricList& metricList, PureAlert& pureAlert) = 0;

    /// Checks if topic is necessary for rule evaluation
    /// @param[in] topic - topic to check
    /// @return true/false
    virtual bool isTopicInteresting(const std::string& topic) const;

    /// Returns a set of topics, that are necessary for rule evaluation
    /// @return a set of topics
    virtual std::vector<std::string> getNeededTopics() const;

public: // methods
    std::string name() const { return _name; }
    void name(const std::string& name) { _name = name; }

    std::string rule_class() const { return _rule_class; }
    void rule_class(const std::string& rule_class) { _rule_class = rule_class; }

    std::string element() const { return _element; }
    void element(const std::string& element) { _element = element; }

    std::map<std::string, double> getGlobalVariables() const { return _variables; }

    /// User is able to define his own set of result, that should be used in evaluation
    ///
    /// Maps result name into the definition of possible outcome.
    /// Outcome name "ok" (case sensitive) for outcome is reserved
    /// and cannot be redefined by user.
    ///
    /// TODO make it private
    std::map<std::string, Outcome> _outcomes;

    /// Checks if rule has this name
    /// @param[in] name - name to check
    /// @return true/false
    bool hasSameNameAs(const std::string& name) const
    {
        return _name == name;
    }

    /// Gets a json representation of the rule
    /// @return json representation of the rule as string
    std::string getJsonRule() const noexcept
    {
        try {
            return JSON::writeToString(_si, true);
        }
        catch (const std::exception& e) {
            log_error("%s, getJsonRule() exception '%s'", _name.c_str(), e.what());
        }
        return "{}";
    };

    /// Save rule to the persistance
    /// assume path with / term
    void save(const std::string& path, const std::string& name) const noexcept
    {
        try {
            const std::string full_name{path + name};
            JSON::writeToFile(full_name, _si, true);
        }
        catch (const std::exception& e) {
            log_error("%s, save() exception '%s'", _name.c_str(), e.what());
        }
    }

    /// Delete rule from the persistance
    /// @param[in] path - a path to files (assume / term)
    /// @return 0 on success, non-zero on error
    int remove(const std::string& path) const noexcept
    {
        const std::string full_name{path + _name + ".rule"};
        log_debug("trying to remove file : '%s'", full_name.c_str());
        return std::remove(full_name.c_str());
    }

    /// RULE_RESULT <-> token
    static std::string resultToString(int result);
    static int resultToInt(const std::string& result);

protected: // properties
    /// json representation (see fill())
    cxxtools::SerializationInfo _si;

    /// Every rule should have a rule name
    /// ASSUMPTION: rule name has only ascii characters.
    /// TODO This assumption is not checked anywhere.
    /// Rule name treated as case INSENSITIVE string
    std::string _name;

    /// Vector of metrics to be evaluated
    std::vector<std::string> _metrics;

    /// The rule source
    std::string _rule_source;

    /// Human readable info about this rule purpose like "internal temperature"
    std::string _rule_class;

    /// Every rule produces alerts for element
    std::string _element;

private: // properties
    /// To define its own constant variables (as thresholds) that can be used
    /// in evaluation function. Maps variable name and its the value.
    std::map<std::string, double> _variables;
};

///
/// Rule matchers
///

class RuleMatcher
{
public:
    virtual bool operator()(const Rule& rule) = 0;

protected:
    virtual ~RuleMatcher() = default;
};

class RuleNameMatcher : public RuleMatcher
{
public:
    RuleNameMatcher(const std::string& name);
    bool operator()(const Rule& rule) override;

private:
    std::string _name;
};

class RuleElementMatcher : public RuleMatcher
{
public:
    RuleElementMatcher(const std::string& element);
    bool operator()(const Rule& rule) override;

private:
    std::string _element;
};
