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

#include "rule.h"
#include "misc/utils.h"

#include <cxxtools/utf8.h>

void si_getValueUtf8(const cxxtools::SerializationInfo& si, const std::string& member_name, std::string& result)
{
    cxxtools::String cxxStr; //native unicode
    si.getMember(member_name) >>= cxxStr;
    result = cxxtools::Utf8(cxxStr);
}

/// Parse of outcome
void operator >>= (const cxxtools::SerializationInfo& si, Outcome& outcome)
{
    outcome._actions.clear();

    const cxxtools::SerializationInfo& actions = si.getMember("action");
    for (const auto& a : actions) {
        switch (a.category()) {
            case cxxtools::SerializationInfo::Value:
                // old-style format ["EMAIL", "SMS"]
                outcome._actions.resize(outcome._actions.size() + 1);
                a >>= outcome._actions.back();
                break;
            case cxxtools::SerializationInfo::Object: {
                std::string type, res;
                // [{"action": "EMAIL"}, {"action": "SMS"}]
                a.getMember("action") >>= type;
                if (type == "EMAIL" || type == "SMS" || type == "AUTOMATION") {
                    res = type;
                }
                else if (type == "GPO_INTERACTION") {
                    std::string asset, mode;
                    a.getMember("asset") >>= asset;
                    a.getMember("mode") >>= mode;
                    res = type + ":" + asset + ":" + mode;
                }
                else {
                    log_warning("Unknown action type: '%s'", type.c_str());
                    res = type;
                }
                outcome._actions.push_back(res);
                break;
            }
            default:
                throw std::runtime_error("Invalid format of action");
        }
    }
    si.getMember("description") >>= outcome._description;
}

/// Parse of named values (variables)
/// TODO error handling mistakes can be hidden here
void operator >>= (const cxxtools::SerializationInfo& si, std::map<std::string, double>& values)
{
    /**
       "values":[ {"low_critical"  : "30"},
                  {"low_warning"   : "40"},
                  {"high_warning"  : "50"},
                  {"high_critical" : "60"} ]
    */
    for (const auto& oneElement : si) { // iterate through the array
        auto        variableName = oneElement.getMember(0).name();
        std::string valueString;
        oneElement.getMember(0) >>= valueString;
        try {
            size_t pos = 0;
            double valueDouble = std::stod(valueString, &pos);
            if (pos != valueString.length()) {
                throw std::invalid_argument("Value should be double");
            }
            values.emplace(variableName, valueDouble);
        }
        catch (const std::exception& e) {
            log_error("Value '%s' is not double (%s)", valueString.c_str(), e.what());
            throw std::runtime_error("Value should be double");
        }
    }
}

/// Parse of results, array of named outcomes
void operator >>= (const cxxtools::SerializationInfo& si, std::map<std::string, Outcome>& outcomes)
{
    /**
        "results": [
            {"low_critical"  : { "action" : [{ "action": "EMAIL"},{ "action": "SMS"}], "description" : "low critical description" }},
            {"low_warning"   : { "action" : [{ "action": "EMAIL"}], "description" : "low warning description" }},
            {"high_warning"  : { "action" : [{ "action": "EMAIL"}], "description" : "high warning description" }},
            {"high_critical" : { "action" : [{ "action": "EMAIL"}], "description" : "high critical description" }}
       ]
    */
    for (const auto& oneElement : si) { // iterate through the array
        // we should ensure that only one member is present
        if (oneElement.memberCount() != 1) {
            throw std::runtime_error("unexpected member count element in results");
        }

        const std::string outcomeToken = oneElement.getMember(0).name();
        int outcomeResult = Rule::resultToInt(outcomeToken);

        std::string severity;
        switch (outcomeResult) {
            case RULE_RESULT_LOW_CRITICAL:
            case RULE_RESULT_HIGH_CRITICAL:
                severity = "CRITICAL";
                break;
            case RULE_RESULT_LOW_WARNING:
            case RULE_RESULT_HIGH_WARNING:
                severity = "WARNING";
                break;
            default:
                log_error("rule outcome '%s' is not supported (r=%d)", outcomeToken.c_str(), outcomeResult);
                throw std::runtime_error("unsupported result");
        }

        Outcome outcome;
        oneElement.getMember(0) >>= outcome;
        outcome._severity = severity;

        outcomes.emplace(outcomeToken, outcome);
    }
}

bool Rule::isTopicInteresting(const std::string& topic) const
{
    for (const auto& it : _metrics) {
        if (it == topic)
            { return true; }
    }
    return false;
}

std::vector<std::string> Rule::getNeededTopics() const
{
    return _metrics;
}

/// Gets a json representation of the rule
/// @return json payload
std::string Rule::json() const noexcept
{
    try {
        return JSON::writeToString(_si, true);
    }
    catch (const std::exception& e) {
        log_error("json parser exception (%s, e: %s)", _name.c_str(), e.what());
    }
    return "{}";
}

/// Save rule to the persistance
/// assume path with / term
void Rule::save(const std::string& path, const std::string& name) const noexcept
{
    try {
        const std::string full_name{path + name};
        JSON::writeToFile(full_name, _si, true);
    }
    catch (const std::exception& e) {
        log_error("save() failed (%s, e: %s)", _name.c_str(), e.what());
    }
}

/// Delete rule from the persistance
/// @param[in] path - a path to files (assume / term)
/// @return 0 on success, non-zero on error
int Rule::remove(const std::string& path) const noexcept
{
    const std::string full_name{path + _name + ".rule"};
    log_debug("remove file '%s'", full_name.c_str());
    return std::remove(full_name.c_str());
}

/// RULE_RESULT tokens map
static const std::map<int, std::string> mapTextResults = {
    { RULE_RESULT_LOW_CRITICAL,  "low_critical"  },
    { RULE_RESULT_LOW_WARNING,   "low_warning"   },
    { RULE_RESULT_OK,            "ok"            },
    { RULE_RESULT_HIGH_WARNING,  "high_warning"  },
    { RULE_RESULT_HIGH_CRITICAL, "high_critical" },
    { RULE_RESULT_UNKNOWN,       "unknown"       },
};

/// RULE_RESULT -> token
std::string Rule::resultToString(int result)
{
    const auto& it = mapTextResults.find(result);
    if (it != mapTextResults.cend())
        { return it->second; }
    return mapTextResults.find(RULE_RESULT_UNKNOWN)->second;
}

/// token -> RULE_RESULT
int Rule::resultToInt(const std::string& result)
{
    for (const auto& it : mapTextResults) {
        if (result == it.second)
            { return it.first; }
    }
    return RULE_RESULT_UNKNOWN;
}

///
/// Rule matchers
///

RuleNameMatcher::RuleNameMatcher(const std::string& name) : _name(name) {}

bool RuleNameMatcher::operator()(const Rule& rule)
{
    return rule.name() == _name;
}

RuleElementMatcher::RuleElementMatcher(const std::string& element) : _element(element) {}

bool RuleElementMatcher::operator()(const Rule& rule)
{
    return rule.element() == _element;
}
