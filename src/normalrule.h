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

/*! \file normalrule.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Representation of normal rule
 */
#ifndef SRC_NORMALRULE_H
#define SRC_NORMALRULE_H

#include "luarule.h"
extern "C" {
#include <lua.h>
#include <lauxlib.h>
}
// because of zsys
#include <czmq.h>
class NormalRule : public LuaRule
{
public:
    NormalRule(){};

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
    };

    friend Rule* readRule (std::istream &f);

protected:

    lua_State* setContext (const MetricList &metricList) const
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
        for ( const auto &aConstantValue : _variables ) {
            lua_pushnumber (lua_context, aConstantValue.second);
            lua_setglobal (lua_context, aConstantValue.first.c_str());
        }
        // we are here -> all constants are set
        return lua_context;
    };


};

#endif // SRC_NORMALRULE_H_
