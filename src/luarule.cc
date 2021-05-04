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

/*! \file luaRule.cc
 *  \author Tomas Halman <TomasHalman@eaton.com>
 *  \brief Class implementing Lua rule evaluation
 */
#include <czmq.h>
#include <fty_log.h>
#include <algorithm>
extern "C" {
#include <lualib.h>
#include <lauxlib.h>
}
#include "luarule.h"
#include "fty_alert_engine_audit_log.h"

LuaRule::~LuaRule ()
{
   if (_lstate) lua_close (_lstate);
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

#if LUA_VERSION_NUM > 501
    _lstate = luaL_newstate();
#else
    _lstate = lua_open();
#endif
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

int LuaRule::evaluate (const MetricList &metricList, PureAlert &pureAlert)
{
    log_debug("LuaRule::evaluate %s", _name.c_str());
    int res = 0;

    std::vector<double> values;
    std::vector<std::string> auditValues;
    int index = 0;
    for ( const auto &metric : _metrics ) {
        double value = metricList.find (metric);
        if ( std::isnan (value) ) {
            log_debug("metric#%d: %s = NaN", index, metric.c_str());
            log_debug("Don't have everything for '%s' yet", _name.c_str());
            std::stringstream ss;
            ss << metric.c_str() << " = " << "NaN";
            auditValues.push_back(ss.str());
            res = RULE_RESULT_UNKNOWN;
            break;
        }
        values.push_back(value);
        log_debug("metric#%d: %s = %lf", index, metric.c_str(), value);
        std::stringstream ss;
        ss << metric.c_str() << " = " << value;
        auditValues.push_back(ss.str());
        index++;
    }

    if (res != RULE_RESULT_UNKNOWN) {
        int status = static_cast<int>(luaEvaluate(values));
        const char *statusText = resultToString (status);
        //log_debug("LuaRule::evaluate on %s gives '%s'", _name.c_str(), statusText);

        auto outcome = _outcomes.find (statusText);
        if ( outcome != _outcomes.cend() ) {
            log_debug("LuaRule::evaluate %s START %s", _name.c_str(), outcome->second._severity.c_str());

            // some known outcome was found
            pureAlert = PureAlert(ALERT_START, static_cast<uint64_t>(::time(NULL)), outcome->second._description, _element, outcome->second._severity, outcome->second._actions);
            pureAlert.print();
        }
        else if ( status == RULE_RESULT_OK ) {
            log_debug("LuaRule::evaluate %s %s", _name.c_str(), "RESOLVED");

            // When alert is resolved, it doesn't have new severity!!!!
            pureAlert = PureAlert(ALERT_RESOLVED, static_cast<uint64_t>(::time(NULL)), "everything is ok", _element, "OK", {""});
            pureAlert.print();
        }
        else {
            log_error ("LuaRule::evaluate %s has returned a result %s, but it is not specified in 'result' in the JSON rule definition", _name.c_str(), statusText);
            res = RULE_RESULT_UNKNOWN;
        }
    }
    std::stringstream ss;
    std::for_each(begin(auditValues), end(auditValues), [&ss](const std::string &elem) { if (ss.str().empty()) ss << elem; else ss << ", " << elem; } );
    log_info_alarms_engine_audit("Evaluate rule '%s' [%s] -> %s %s", _name.c_str(), ss.str().c_str(), (res == RULE_RESULT_UNKNOWN) ? ALERT_UNKNOWN : pureAlert._status.c_str(), (res == RULE_RESULT_UNKNOWN) ? "" : pureAlert._severity.c_str());
    return res;
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
    if (lua_pcall (_lstate, static_cast<int>(metrics.size ()), 1, 0) != 0) {
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
