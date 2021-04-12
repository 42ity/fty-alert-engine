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

#include "fty_alert_engine_classes.h"
#include <fty/convert.h>

// 1, ..., 4 - # of utf8 octets
// -1 - error 
static int8_t
utf8_octets (const std::string& s, std::string::size_type pos)
{
    assert (pos < s.length ());

    const char c = s[pos];
    if ((c & 0x80 ) == 0) {     // lead bit is zero, must be a single ascii
        return 1;
    }
    else
    if ((c & 0xE0 ) == 0xC0 ) { // 110x xxxx (2 octets)
        return 2;
    }
    else
    if ((c & 0xF0 ) == 0xE0 ) { // 1110 xxxx (3 octets)
        return 3;
    }
    else
    if ((c & 0xF8 ) == 0xF0 ) { // 1111 0xxx (4 octets)
        return 4;
    }
    else {
        log_error ("Unrecognized utf8 lead byte '%x' in string '%s'", c, s.c_str ());
        return -1;
    }
}

// 0 - same
// 1 - different
static int
utf8_compare_octets (const std::string& s1, std::string::size_type s1_pos, const std::string& s2, std::string::size_type s2_pos, uint8_t count)
{
    assert (count >= 1 && count <= 4);
    assert (s1_pos + count <= s1.length ());
    assert (s2_pos + count <= s2.length ());

    for (int i = 0; i < count; i++) {
        const char c1 = s1[s1_pos + fty::convert<size_t>(i)];
        const char c2 = s2[s2_pos + fty::convert<size_t>(i)];

        if ((count == 1 && tolower (c1) != tolower (c2)) ||
            (count > 1  && c1 != c2))
            return 1;
    }
    return 0;
}

int
utf8eq (const std::string& s1, const std::string& s2)
{
    if (s1.length () != s2.length ())
        return 0;

    std::string::size_type s1_pos = 0, s2_pos = 0;
    std::string::size_type length = s1.length ();


    while (s1_pos < length &&
           s2_pos < length)
    {
        uint8_t s1_octets = static_cast<uint8_t>(utf8_octets (s1, s1_pos));
        uint8_t s2_octets = static_cast<uint8_t>(utf8_octets (s2, s2_pos));

        if (s1_octets == UINT8_MAX || s2_octets == UINT8_MAX)
            return -1;

        if (s1_octets != s2_octets)
            return 0;
        
        if (utf8_compare_octets (s1, s1_pos, s2, s2_pos, s1_octets) == 1)
            return 0;
        
        s1_pos = s1_pos + s1_octets;
        s2_pos = s2_pos + s1_octets;
    }
    return 1;
}

void
si_getValueUtf8 (const cxxtools::SerializationInfo& si, const std::string& member_name, std::string& result)
{
    std::basic_string <cxxtools::Char> cxxtools_Char_name;
    si.getMember (member_name).getValue (cxxtools_Char_name);
    result = cxxtools::Utf8Codec::encode (cxxtools_Char_name);
}

/*
 * \brief Deserialization of outcome
 */
void operator>>= (const cxxtools::SerializationInfo& si, Outcome& outcome)
{
    const cxxtools::SerializationInfo &actions = si.getMember("action");
    outcome._actions.clear();
    outcome._actions.reserve(actions.memberCount());
    for ( const auto &a : actions) {
        std::string type, res;
        switch (a.category()) {
        case cxxtools::SerializationInfo::Value:
            // old-style format ["EMAIL", "SMS"]
            outcome._actions.resize(outcome._actions.size() + 1);
            a >>= outcome._actions.back();
            break;
        case cxxtools::SerializationInfo::Object:
            // [{"action": "EMAIL"}, {"action": "SMS"}]
            a.getMember("action") >>= type;
            if (type == "EMAIL" || type == "SMS" || type == "AUTOMATION") {
                res = type;
            } else if (type == "GPO_INTERACTION") {
                std::string asset, mode;
                a.getMember("asset") >>= asset;
                a.getMember("mode") >>= mode;
                res = type + ":" + asset + ":" + mode;
            } else {
                log_warning("Unknown action type: \"%s\"", type.c_str());
                res = type;
            }
            outcome._actions.push_back(res);
            break;
        default:
            throw std::runtime_error("Invalid format of action");
        }
    }
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
        std::size_t pos = 0;
        try {
            double valueDouble = std::stod (valueString, &pos);
            if  ( pos != valueString.length() ) {
                throw std::invalid_argument("Value should be double");
            }
            values.emplace (variableName, valueDouble);
        }
        catch (const std::exception &e ) {
            log_error ("Value '%s' is not double", valueString.c_str());
            throw std::runtime_error("Value should be double");
        }
    }
}
// TODO error handling mistakes can be hidden here
void operator>>= (const cxxtools::SerializationInfo& si, std::map <std::string, Outcome> &outcomes)
{
    /*
        "results":[ {"low_critical"  : { "action" : [{ "action": "EMAIL"},{ "action": "SMS"}], "description" : "WOW low critical description" }},
                    {"low_warning"   : { "action" : [{ "action": "EMAIL"}], "description" : "wow LOW warning description"}},
                    {"high_warning"  : { "action" : [{ "action": "EMAIL"}], "description" : "wow high WARNING description" }},
                    {"high_critical" : { "action" : [{ "action": "EMAIL"}], "description" : "wow high critical DESCTIPRION" } } ]
    */
    for ( const auto &oneElement : si ) { // iterate through the array
        //we should ensure that only one member is present
        if(oneElement.memberCount()!=1){
            throw std::runtime_error ("unexpected member count element in results");
        }
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
        if (utf8eq (item, topic))
            return true;
    }
    return false;
}

std::vector<std::string> Rule::getNeededTopics(void) const {
    return _metrics;
}


RuleNameMatcher::RuleNameMatcher(const std::string &name) :
    _name(name) {
}

bool RuleNameMatcher::operator()(const Rule &rule) {
    return rule.name() == _name;
}

RuleElementMatcher::RuleElementMatcher(const std::string &element) :
    _element(element) {
}

bool RuleElementMatcher::operator()(const Rule &rule) {
    return rule.element() == _element;
}
