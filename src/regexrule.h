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

/*! \file regexrule.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Representation of regex rule
 */
#ifndef SRC_REGEXRULE_H
#define SRC_REGEXRULE_H

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}
// because of regex and zsysinfo
#include <czmq.h>
#include "luarule.h"

class RegexRule : public LuaRule {
public:

    RegexRule()
    {
        _rex = NULL;
    };

    int evaluate (const MetricList &metricList, PureAlert **pureAlert) const
    {
        lua_State *lua_context = setContext (metricList);
        if ( lua_context == NULL ) {
            // not possible to evaluate metric with current known Metrics
            return 2;
        }

        zsys_info ("lua_code = %s", _code.c_str() );
        int error = luaL_loadbuffer (lua_context, _code.c_str(), _code.length(), "line") ||
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
        std::string element = metricList.getLastMetric().getElementName();
        // ok, in the lua stack we got, what we expected
        const char *status = lua_tostring(lua_context, -1); // "ok" or result name
        auto outcome = _outcomes.find (status);
        if ( outcome != _outcomes.cend() )
        {
            // some known outcome was found
            *pureAlert = new PureAlert(ALERT_START, ::time(NULL), outcome->second._description, element, outcome->second._severity, outcome->second._actions);
            (**pureAlert).print();
            lua_close (lua_context);
            return 0;
        }
        if ( streq (status, "ok") )
        {
            // When alert is resolved, it doesn't have new severity!!!!
            *pureAlert = new PureAlert(ALERT_RESOLVED, ::time(NULL), "everithing is ok", element, "DOESN'T MATTER", {""});
            (**pureAlert).print();
            lua_close (lua_context);
            return 0;
        }
        zsys_error ("unknown result '%s' received from lua function", status);
        lua_close (lua_context);
        return -1;
    };

    bool isTopicInteresting(const std::string &topic) const
    {
        return zrex_matches (_rex, topic.c_str());
    };

    std::vector<std::string> getNeededTopics(void) const
    {
        return std::vector<std::string>{_rex_str};
    };

    friend Rule* readRule (std::istream &f);

protected:

    lua_State* setContext (const MetricList &metricList) const
    {
        lua_State *lua_context = lua_open();
        // 1 ) set up metric
        lua_pushnumber(lua_context, metricList.getLastMetric().getValue());
        lua_setglobal(lua_context, "value");

        //  2 ) set up variables
        for ( const auto &aConstantValue : _variables ) {
            lua_pushnumber (lua_context, aConstantValue.second);
            lua_setglobal (lua_context, aConstantValue.first.c_str());
        }
        // we are here -> all constants are set
        return lua_context;
    };

private:
    zrex_t *_rex;
    std::string _rex_str;
};

#endif // SRC_REGEXRULE_H
