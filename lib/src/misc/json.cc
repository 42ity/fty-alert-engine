/*
Copyright (C) 2014 - 2025 Eaton

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

/// json cxxtools utilities

#include "json.h"

#include <fty_log.h>
#include <cxxtools/utf8.h>

namespace JSON {

const cxxtools::SerializationInfo* findMember(const cxxtools::SerializationInfo& si, const std::string& name)
{
    return si.findMember(name);
}

const cxxtools::SerializationInfo* findMember(const cxxtools::SerializationInfo* p, const std::string& name)
{
    return p ? p->findMember(name) : nullptr;
}

bool isObject(const cxxtools::SerializationInfo* p)
{
    return p && (p->category() == cxxtools::SerializationInfo::Object);
}

bool isArray(const cxxtools::SerializationInfo* p)
{
    return p && (p->category() == cxxtools::SerializationInfo::Array);
}

bool isValue(const cxxtools::SerializationInfo* p)
{
    return p && (p->category() == cxxtools::SerializationInfo::Value);
}

// throw on error (p changed)
void setObjectProperty(cxxtools::SerializationInfo* p, const std::string& property, const std::string& value)
{
    try {
        if (!isObject(p)) {
           throw std::invalid_argument("Object member expected");
        }

        auto x = p->findMember(property);
        if (x) { *x <<= value; }
        else { p->addMember(property) <<= value; }
    }
    catch (const std::exception& e) {
        const std::string err{"setObjectProperty(), e: " + std::string(e.what())};
        log_error("%s", err.c_str());
        throw std::runtime_error(err);
    }
}

std::string getStringUtf8(const cxxtools::SerializationInfo* p)
{
    cxxtools::String cxxStr; // native unicode
    if (isValue(p)) { *p >>= cxxStr; }
    return cxxtools::Utf8(cxxStr);
}

std::string getString(const cxxtools::SerializationInfo* p)
{
    std::string s;
    if (isValue(p)) { *p >>= s; }
    return s;
}

// throw on error
std::map<std::string, double> getMapDouble(const cxxtools::SerializationInfo* p)
{
    /** [ {"low_critical"  : "30"},
          {"low_warning"   : "40"},
          {"high_warning"  : "50"},
          {"high_critical" : "60"} ]
    */

    std::map<std::string, double> ret;

    try {
        if (!isArray(p)) {
           throw std::invalid_argument("Array member expected");
        }

        for (const auto& it : *p) { // iterate through the array
            auto o = it.getMember(0);
            auto name = o.name();
            auto svalue = getString(&o);
            // check value is double
            size_t pos{0};
            double value = std::stod(svalue, &pos);
            if (pos != svalue.length()) {
                throw std::invalid_argument("Float value expected");
            }
            ret.emplace(name, value);
        }
    }
    catch (const std::exception& e) {
        const std::string err{"getMapDouble(), e: " + std::string(e.what())};
        log_error("%s", err.c_str());
        throw std::runtime_error(err);
    }

    return ret;
}

// throw on error
std::vector<std::string> getActions(const cxxtools::SerializationInfo* p)
{
    /** [ "EMAIL", "SMS" ]
    or
        [ {"action" : "EMAIL"}, {"action" : "SMS"} ]
    */

    std::vector<std::string> actions;

    try {
        if (!isArray(p)) {
           throw std::invalid_argument("Array member expected");
        }

        for (const auto& it : *p) { // iterate through the array
            if (isValue(&it)) {
                // old style format ["EMAIL", "SMS"]
                actions.push_back(getString(&it));
            }
            else if (isObject(&it)) {
                // rich style format [{"action": "EMAIL"}, {"action": "SMS"}]
                auto action = findMember(&it, "action");
                if (!isValue(action)) {
                    throw std::invalid_argument("Value member expected");
                }

                std::string value = getString(action);

                if (value == "GPO_INTERACTION") {
                    // fmt exception (addons)
                    std::string asset = getString(findMember(&it, "asset"));
                    std::string mode = getString(findMember(&it, "mode"));
                    value += ":" + asset + ":" + mode;
                }
                else if ((value == "EMAIL")
                        || (value == "SMS")
                        || (value == "AUTOMATION")
                ) {
                    // nop (known values)
                }
                else {
                    log_warning("Unknown action: '%s'", value.c_str());
                }

                actions.push_back(value);
            }
            else {
                throw std::runtime_error("Invalid action format");
            }
        }
    }
    catch (const std::exception& e) {
        const std::string err{"getActions(), e: " + std::string(e.what())};
        log_error("%s", err.c_str());
        throw std::runtime_error(err);
    }

    return actions;
}

// throw on error
static Outcome getOutcome(const cxxtools::SerializationInfo* p)
{
    /**
        { "action" : [{ "action": "EMAIL"}, { "action": "SMS"}], "description" : "low critical description" }
    */

    Outcome outcome;

    try {
        if (!isObject(p)) {
           throw std::invalid_argument("Object member expected");
        }

        outcome._actions = getActions(findMember(p, "action"));
        outcome._description = getString(findMember(p, "description"));
        //no severity
    }
    catch (const std::exception& e) {
        const std::string err{"getOutcome(), e: " + std::string(e.what())};
        log_error("%s", err.c_str());
        throw std::runtime_error(err);
    }

    return outcome;
}

// throw on error
std::map<std::string, Outcome> getMapOutcome(const cxxtools::SerializationInfo* p)
{
    /**
        [
            {"low_critical"  : { "action" : [{ "action": "EMAIL"},{ "action": "SMS"}], "description" : "low critical description" }},
            {"low_warning"   : { "action" : [{ "action": "EMAIL"}], "description" : "low warning description" }},
            {"high_warning"  : { "action" : [{ "action": "EMAIL"}], "description" : "high warning description" }},
            {"high_critical" : { "action" : [{ "action": "EMAIL"}], "description" : "high critical description" }}
       ]
    */

    std::map<std::string, Outcome> outcomes;

    try {
        if (!isArray(p)) {
           throw std::invalid_argument("Array member expected");
        }

        for (const auto& it : *p) { // iterate through the array
            // we should ensure that only one member/object is present
            if (it.memberCount() != 1) {
                throw std::runtime_error("Unique member expected");
            }
            const auto item = it.getMember(0);
            if (!isObject(&item)) {
                throw std::runtime_error("Object member expected");
            }

            const std::string outcomeToken = item.name();

            std::string severity;
            switch (outcome::resultToInt(outcomeToken)) {
                case outcome::RULE_RESULT_LOW_CRITICAL:
                case outcome::RULE_RESULT_HIGH_CRITICAL:
                    severity = "CRITICAL";
                    break;
                case outcome::RULE_RESULT_LOW_WARNING:
                case outcome::RULE_RESULT_HIGH_WARNING:
                    severity = "WARNING";
                    break;
                default:
                    const std::string err{"outcome '" + outcomeToken + "' is not supported"};
                    log_error("%s", err.c_str());
                    throw std::runtime_error(err);
            }

            Outcome outcome = getOutcome(&item);
            outcome._severity = severity;

            outcomes.emplace(outcomeToken, outcome);
        }
    }
    catch (const std::exception& e) {
        const std::string err{"getMapOutcome(), e: " + std::string(e.what())};
        log_error("%s", err.c_str());
        throw std::runtime_error(err);
    }

    return outcomes;
}

} //namespace
