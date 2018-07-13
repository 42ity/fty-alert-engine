/*
Copyright (C) 2014 - 2017 Eaton

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

/*! \file regexrule.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Representation of PATTERN rule
 */
#ifndef SRC_REGEXRULE_H
#define SRC_REGEXRULE_H

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}
// because of regex and zsysinfo
#include <czmq.h>
#include <fty_log.h>
#include "luarule.h"

class RegexRule : public LuaRule {
public:

    RegexRule()
    {
        _rex = NULL;
    };

    ~RegexRule() {
        zrex_destroy (&_rex);
    };

    std::string whoami () const { return "pattern"; }

    /*
     * \brief parse json and check lua and fill the object
     *
     * ATTENTION: throws, if bad JSON
     *
     * \return 1 if rule has other type
     *         2 if lua function has errors
     *         0 if everything is ok
     */
    int fill(const cxxtools::SerializationInfo &si)
    {
        _si = si;
        if ( si.findMember("pattern") == NULL ) {
            return 1;
        }
        log_debug ("it is PATTERN rule");
        auto pattern = si.getMember("pattern");
        if ( pattern.category () != cxxtools::SerializationInfo::Object ) {
            log_error ("Root of json must be an object with property 'pattern'.");
            throw std::runtime_error("Root of json must be an object with property 'pattern'.");
        }

        pattern.getMember("rule_name") >>= _name;
        pattern.getMember("target") >>= _rex_str;
        // rule_class
        if ( pattern.findMember("rule_class") != NULL ) {
            pattern.getMember("rule_class") >>= _rule_class;
        }
        // rule_source
        if ( pattern.findMember("rule_source") == NULL ) {
            // if key is not there, take default
            _rule_source = "Manual user input";
            pattern.addMember("rule_source") <<= _rule_source;
        }
        else {
            auto rule_source = pattern.getMember("rule_source");
            if ( rule_source.category () != cxxtools::SerializationInfo::Value ) {
                throw std::runtime_error("'rule_source' in json must be value.");
            }
            rule_source >>= _rule_source;
        }
        log_debug ("rule_source = %s", _rule_source.c_str());

        // values
        std::map<std::string,double> tmp_values;
        auto values = pattern.getMember("values");
        if ( values.category () != cxxtools::SerializationInfo::Array ) {
            log_error ("parameter 'values' in json must be an array.");
            throw std::runtime_error("parameter 'values' in json must be an array");
        }
        values >>= tmp_values;
        globalVariables(tmp_values);

        // outcomes
        auto outcomes = pattern.getMember("results");
        if ( outcomes.category () != cxxtools::SerializationInfo::Array ) {
            log_error ("parameter 'results' in json must be an array.");
            throw std::runtime_error ("parameter 'results' in json must be an array.");
        }
        outcomes >>= _outcomes;

        std::string tmp;
        pattern.getMember("evaluation") >>= tmp;
        try {
            code(tmp);
        }
        catch ( const std::exception &e ) {
            log_error ("something with lua function: %s", e.what());
            return 2;
        }
        // TODO what if regexp is not correct?
        _rex = zrex_new(_rex_str.c_str());
        return 0;
    };

    int evaluate (const MetricList &metricList, PureAlert &pureAlert)
    {
        _metrics = {metricList.getLastMetric().generateTopic()};
        int rv = LuaRule::evaluate(metricList, pureAlert);
        if ( rv != 0 ) {
            return rv;
        }
        // regexp rule is special, it has to generate alert for the element,
        // that triggert the evaluation
        pureAlert._element = metricList.getLastMetric().getElementName();
        return 0;
    };

    bool isTopicInteresting(const std::string &topic) const
    {
        return zrex_matches (_rex, topic.c_str());
    };

    std::vector<std::string> getNeededTopics(void) const
    {
        return std::vector<std::string>{_rex_str};
    };

private:
    zrex_t *_rex;
    std::string _rex_str;
};

#endif // SRC_REGEXRULE_H
