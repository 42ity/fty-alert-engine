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
        size_t i = 0;
        for (auto& a : _actions)
            { oss << "actions[" << i++ << "](" << a << "),"; }
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
    virtual std::string clazz() const { return "/Rule"; }

    /// Initialize the rule from SerializationInfo (json)
    /// @param[in] si - a SerializationInfo object
    /// @return 0 if the rule is recognized and initialized correctly
    ///         1 if the rule is not recognized
    ///         2 if an error occured (bad json object)
    virtual int fill(const cxxtools::SerializationInfo& si) = 0;

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

    // LuaRule virtual requirement
    virtual void globalVariables(const std::map<std::string, double>& variables) { _variables = variables; }

public: // methods
    std::string name() const { return _name; }

    std::string rule_class() const { return _rule_class; }

    std::string element() const { return _element; }

    std::map<std::string, double> globalVariables() const { return _variables; }

    std::map<std::string, Outcome> outcomes() const { return _outcomes; }
    Outcome outcome(const std::string& key) const { return (_outcomes.count(key) != 0) ? _outcomes.at(key) : Outcome(); }

    /// Gets a json representation of the rule
    /// @return json payload
    std::string json() const noexcept;

    /// Save rule to the persistance
    /// assume path with / term
    void save(const std::string& path, const std::string& name) const noexcept;

    /// Delete rule from the persistance
    /// @param[in] path - a path to files (assume / term)
    /// @return 0 on success, non-zero on error
    int remove(const std::string& path) const noexcept;

    /// RULE_RESULT <-> token
    static std::string resultToString(int result);
    static int resultToInt(const std::string& result);

protected: // properties
    /// json representation (see fill())
    cxxtools::SerializationInfo _si;

    /// Every rule should have a rule name
    std::string _name;

    /// Vector of metrics to be evaluated (aka topics)
    std::vector<std::string> _metrics;

    /// The rule source
    std::string _rule_source;

    /// Human readable info about this rule purpose like "internal temperature"
    std::string _rule_class;

    /// Every rule produces alerts for element/asset
    std::string _element;

    /// User is able to define his own set of result, that should be used in evaluation
    /// Maps result name into the definition of possible outcome.
    /// Outcome name "ok" (case sensitive) for outcome is reserved
    /// and cannot be redefined by user.
    std::map<std::string, Outcome> _outcomes;

private: // properties
    /// To define its own constant variables (as threshold values) that can be used
    /// for evaluation. Maps variable name and its value.
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
