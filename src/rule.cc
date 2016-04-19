/*
Copyright (C) 2014 - 2015 Eaton

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

#include "rule.h"

/*
 * \brief Serialzation of outcome
 */
void operator<<= (cxxtools::SerializationInfo& si, const Outcome& outcome)
{
    si.addMember("action") <<= outcome._actions;
    si.addMember("description") <<= outcome._description;
}

/*
 * \brief Deserialzation of outcome
 */
void operator>>= (const cxxtools::SerializationInfo& si, Outcome& outcome)
{
    si.getMember("action") >>= outcome._actions;
    si.getMember("description") >>= outcome._description;
}

// TODO error handling mistakes can be hidden here
void operator>>= (const cxxtools::SerializationInfo& si, std::map <std::string, double> &values)
{
    /*
       "values":[ {"low_critical"  : "30"},
                  {"low_warning"   : "40"},
                  {"high_warning"  : "50"},
                  {"high_critical" : "60"} ]
    */
    for ( const auto &oneElement : si ) { // iterate through the array
        auto variableName = oneElement.getMember(0).name();
        std::string valueString;
        oneElement.getMember(0) >>= valueString;
        double valueDouble = std::stod (valueString);
        values.emplace (variableName, valueDouble);
    }
}
// TODO error handling mistakes can be hidden here
void operator>>= (const cxxtools::SerializationInfo& si, std::map <std::string, Outcome> &outcomes)
{
    /*
        "results":[ {"low_critical"  : { "action" : ["EMAIL","SMS"], "description" : "WOW low critical description" }},
                    {"low_warning"   : { "action" : ["EMAIL"], "description" : "wow LOW warning description"}},
                    {"high_warning"  : { "action" : ["EMAIL"], "description" : "wow high WARNING description" }},
                    {"high_critical" : { "action" : ["EMAIL"], "description" : "wow high critical DESCTIPRION" } } ]
    */
    for ( const auto &oneElement : si ) { // iterate through the array
        auto outcomeName = oneElement.getMember(0).name();
        Outcome outcome;
        oneElement.getMember(0) >>= outcome;
        if ( outcomeName == "low_critical" || outcomeName == "high_critical" ) {
            outcome._severity = "CRITICAL";
        }
        if ( outcomeName == "low_warning" || outcomeName == "high_warning" ) {
            outcome._severity = "WARNING";
        }
        if ( outcome._severity.empty() ) {
            throw std::runtime_error ("unsupported result");
        }
        outcomes.emplace (outcomeName, outcome);
    }
}

bool Rule::isTopicInteresting(const std::string &topic) const {
    // ok this is o(n) but we will have up to 3 topics in vector
    // TODO: find other model
    for ( const auto &item : _metrics ) {
        if (item == topic) return true;
    }
    return false;
}

std::vector<std::string> Rule::getNeededTopics(void) const {
    return _metrics;
}
