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

/*! \file luaRule.cc
 *  \author Tomas Halman <TomasHalman@eaton.com>
 *  \brief Class implementing Lua rule evaluation
 */

#include "luarule.h"

#include<algorithm>
extern "C" {
#include<lualib.h>
#include<lauxlib.h>
}

LuaRule::LuaRule (const LuaRule &r)
{
    _name = r._name;
    globalVariables (r.getGlobalVariables());
    code (r._code);
}


void LuaRule::globalVariables (const std::map<std::string,double> &vars)
{
    Rule::globalVariables(vars);
    _setGlobalVariablesToLUA();
}

void LuaRule::code (const std::string &newCode)
{
    if (_lstate) lua_close (_lstate);
    _valid = false;
    _code.clear();

    _lstate = lua_open();
    if (! _lstate) {
        throw std::runtime_error("Can't initiate LUA context!");
    }
    luaL_openlibs(_lstate); // get functions like print();

    // set global variables
    _setGlobalVariablesToLUA();

    // set code, try to compile it
    _code = newCode;
    int error = luaL_dostring (_lstate, _code.c_str());
    _valid = (error == 0);
    if (! _valid) {
        throw std::runtime_error("Invalid LUA code!");
    }

    // check wether there is main() function
    lua_getglobal (_lstate, "main");
    if (! lua_isfunction (_lstate, lua_gettop (_lstate))) {
        // main() missing
        _valid = false;
        throw std::runtime_error("Function main not found!");
    }
}

int LuaRule::evaluate (const MetricList &metricList, PureAlert **pureAlert)
{
    std::vector<double> values;
    for ( const auto &metric : _metrics ) {
        double value = metricList.find (metric);
        if ( isnan (value) ) {
            zsys_info("Don't have everything for '%s' yet\n", _name.c_str());
            return RULE_RESULT_UNKNOWN;
        }
        values.push_back(value);
    }
    int status = luaEvaluate(values);
    const char *statusText = resultToString (status);
    auto outcome = _outcomes.find (statusText);
    if ( outcome != _outcomes.cend() ) {
        // some known outcome was found
        *pureAlert = new PureAlert(ALERT_START, ::time(NULL), outcome->second._description, _element, outcome->second._severity, outcome->second._actions);
        (**pureAlert).print();
        return status;
    }
    if ( status == RULE_RESULT_OK ) {
        // When alert is resolved, it doesn't have new severity!!!!
        *pureAlert = new PureAlert(ALERT_RESOLVED, ::time(NULL), "everithing is ok", _element, "DOESN'T MATTER", {""});
        (**pureAlert).print();
        return status;
    }
    zsys_error ("unknown result received from lua function");
    return RULE_RESULT_UNKNOWN;
}

double LuaRule::luaEvaluate(const std::vector<double> &metrics)
{
    double result;

    if (! _valid) { throw std::runtime_error("Rule is not valid!"); }
    lua_settop (_lstate, 0);

    lua_getglobal (_lstate, "main");
    for (const auto x: metrics) {
        lua_pushnumber (_lstate, x);
    }
    if (lua_pcall (_lstate, metrics.size (), 1, 0) != 0) {
        throw std::runtime_error("LUA calling main() failed!");
    }
    if (!lua_isnumber (_lstate, -1)) {
        throw std::runtime_error("LUA main function did not returned number!");
    }
    result = lua_tonumber (_lstate, -1);
    lua_pop (_lstate, 1);
    return result;
}

void LuaRule::_setGlobalVariablesToLUA()
{
    if (_lstate == NULL) return;
    for (int i = RULE_RESULT_TO_LOW_CRITICAL; i <= RULE_RESULT_UNKNOWN; i++) {
        std::string upper = Rule::resultToString(i);
        transform(upper.begin(), upper.end(), upper.begin(), ::toupper);
        lua_pushnumber (_lstate, i);
        lua_setglobal (_lstate, upper.c_str ());
    }
    for (const auto &it : getGlobalVariables() ) {
        lua_pushnumber (_lstate, it.second);
        lua_setglobal (_lstate, it.first.c_str ());
    }
}

