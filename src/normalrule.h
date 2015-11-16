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

#include "rule.h"
extern "C" {
#include <lua.h>
#include <lauxlib.h>
}
// because of zsys
#include <czmq.h>
class NormalRule : public Rule
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

        zsys_info ("lua_code = %s", _lua_code.c_str() );
        int error = luaL_loadbuffer (lua_context, _lua_code.c_str(), _lua_code.length(), "line") ||
            lua_pcall (lua_context, 0, 3, 0);

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
        const char *status_ = lua_tostring(lua_context, -1); // IS / ISNT
        zsys_info ("status = %s", status_ );
        int s = ALERT_UNKNOWN;
        if ( strcmp (status_, "IS") == 0 ) {
            s = ALERT_START;
        }
        else if ( strcmp (status_, "ISNT") == 0 ) {
            s = ALERT_RESOLVED;
        }
        if ( s == ALERT_UNKNOWN ) {
            zsys_info ("unexcpected returned value, expected IS/ISNT\n");
            lua_close (lua_context);
            return -5;
        }
        if ( !lua_isstring(lua_context, -3) ) {
            zsys_info ("unexcpected returned value\n");
            lua_close (lua_context);
            return -3;
        }
        const char *description = lua_tostring(lua_context, -3);
        *pureAlert = new PureAlert(s, ::time(NULL), description, _element);
        printPureAlert (**pureAlert);
        lua_close (lua_context);
        return 0;
    };

    bool isTopicInteresting(const std::string &topic) const
    {
        return ( _in.count(topic) != 0 ? true : false );
    };

    std::set<std::string> getNeededTopics(void) const {
        return _in;
    };

    friend Rule* readRule (std::istream &f);

protected:

    lua_State* setContext (const MetricList &metricList) const
    {
        lua_State *lua_context = lua_open();
        for ( const auto &neededTopic : _in)
        {
            double neededValue = metricList.find (neededTopic);
            if ( isnan (neededValue) ) {
                zsys_info("Do not have everything for '%s' yet\n", _rule_name.c_str());
                lua_close (lua_context);
                return NULL;
            }
            std::string var = neededTopic;
            var[var.find('@')] = '_';
            zsys_info("Setting variable '%s' to %lf\n", var.c_str(), neededValue);
            lua_pushnumber (lua_context, neededValue);
            lua_setglobal (lua_context, var.c_str());
        }
        // we are here -> all variables were found
        return lua_context;
    };

private:

    std::set<std::string> _in;

};

#endif // SRC_NORMALRULE_H_
