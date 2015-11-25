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

/*!
 *  \file thresholdrulecomplex.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Complex threshold rule representation
 */

#include <czmq.h>
#include "thresholdrulecomplex.h"
extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

int ThresholdRuleComplex::
    fill(
        cxxtools::JsonDeserializer &json,
        const std::string &json_string)
{
    const cxxtools::SerializationInfo *si = json.si();
    if ( si->findMember("threshold") == NULL ) {
        return 1;
    }
    auto threshold = si->getMember("threshold");
    if ( threshold.category () != cxxtools::SerializationInfo::Object ) {
        zsys_info ("Root of json must be an object with property 'threshold'.");
        throw std::runtime_error("Root of json must be an object with property 'threshold'.");
    }

    // target
    auto target = threshold.getMember("target");
    if ( target.category () != cxxtools::SerializationInfo::Array ) {
        return 1;
    }
    zsys_info ("it is complex threshold rule");

    target >>= _metrics;
    _json_representation = json_string;
    threshold.getMember("rule_name") >>= _name;
    threshold.getMember("element") >>= _element;
    // values
    // TODO check low_critical < low_warnong < high_warning < hign crtical
    std::map<std::string,double> tmp_values;
    auto values = threshold.getMember("values");
    if ( values.category () != cxxtools::SerializationInfo::Array ) {
        zsys_info ("parameter 'values' in json must be an array.");
        throw std::runtime_error("parameter 'values' in json must be an array");
    }
    values >>= tmp_values;
    globalVariables(tmp_values);

    // outcomes
    auto outcomes = threshold.getMember("results");
    if ( outcomes.category () != cxxtools::SerializationInfo::Array ) {
        zsys_info ("parameter 'results' in json must be an array.");
        throw std::runtime_error ("parameter 'results' in json must be an array.");
    }
    outcomes >>= _outcomes;

    std::string tmp;
    threshold.getMember("evaluation") >>= tmp;
    code(tmp);

    return 0;
}

int ThresholdRuleComplex::evaluate (const MetricList &metricList, PureAlert **pureAlert) const {
        lua_State *lua_context = setContext (metricList);
        if ( lua_context == NULL ) {
            // not possible to evaluate metric with current known Metrics
            return 2;
        }

        zsys_info ("lua_code = %s", code().c_str() );
        int error = luaL_loadbuffer (lua_context, code().c_str(), code().length(), "line") ||
            lua_pcall (lua_context, 0, 1, 0);

        if ( error ) {
            // syntax error in evaluate
            zsys_info ("Syntax error: %s\n", lua_tostring(lua_context, -1));
            lua_close (lua_context);
            return 1;
        }
        // if we are going to use the same context repeatedly -> use lua_pop(lua_context, 1)
        // to pop error message from the stack

        // evaluation was successful, need to read the result
        if ( !lua_isstring (lua_context, -1) ) {
            zsys_info ("unexcpected returned value\n");
            lua_close (lua_context);
            return -1;
        }
        // ok, in the lua stack we got, what we expected
        const char *status = lua_tostring(lua_context, -1); // "ok" or result name
        auto outcome = _outcomes.find (status);
        if ( outcome != _outcomes.cend() )
        {
            // some known outcome was found
            *pureAlert = new PureAlert(ALERT_START, ::time(NULL), outcome->second._description, _element, outcome->second._severity, outcome->second._actions);
            (**pureAlert).print();
            lua_close (lua_context);
            return 0;
        }
        if ( streq (status, "ok") )
        {
            // When alert is resolved, it doesn't have new severity!!!!
            *pureAlert = new PureAlert(ALERT_RESOLVED, ::time(NULL), "everithing is ok", _element, "DOESN'T MATTER", {""});
            (**pureAlert).print();
            lua_close (lua_context);
            return 0;
        }
        zsys_error ("unknown result received from lua function");
        lua_close (lua_context);
        return -1;
}

bool ThresholdRuleComplex::isTopicInteresting(const std::string &topic) const {
    return ( _metrics.count (topic) == 1 );
}

std::set<std::string> ThresholdRuleComplex::getNeededTopics(void) const {
    return _metrics;
}

// Rule* ThresholdRuleComplex::readRule (std::istream &f);

lua_State* ThresholdRuleComplex::setContext (const MetricList &metricList) const
{
    lua_State *lua_context = lua_open();
    // 1 ) set up all necessary metrics
    for ( const auto &aNeededMetric : _metrics ) {
        double neededValue = metricList.find (aNeededMetric);
        if ( isnan (neededValue) ) {
            zsys_info("Do not have everything for '%s' yet\n", _name.c_str());
            lua_close (lua_context);
            return NULL;
        }
        std::string var = aNeededMetric;
        var[var.find('@')] = '_';
        zsys_info("Setting variable '%s' to %lf\n", var.c_str(), neededValue);
        lua_pushnumber (lua_context, neededValue);
        lua_setglobal (lua_context, var.c_str());
    }
    // we are here -> all metrics were found

    //  2 ) set up variables
    for ( const auto &aConstantValue : getGlobalVariables() ) {
        lua_pushnumber (lua_context, aConstantValue.second);
        lua_setglobal (lua_context, aConstantValue.first.c_str());
    }
    // we are here -> all constants are set
    return lua_context;
}

