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

/*! \file thresholdrule.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Representation of threshold rule
 */
#ifndef SRC_THRESHOLDRULE_H
#define SRC_THRESHOLDRULE_H

#include "rule.h"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

class ThresholdRule : public Rule
{
public:

    ThresholdRule(){};

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
        return ( _in == topic ? true : false );
    };

    std::set<std::string> getNeededTopics(void) const {
        return {_in};
    };

    friend Rule* readRule (std::istream &f);

protected:

    void generateLua (void)
    {
        // assumption: at this point type can have only two values
        if ( _type == "low" )
        {
            _lua_code = "if ( ";
            _lua_code += _metric;
            _lua_code += "_";
            _lua_code += _element;
            _lua_code += " <  ";
            _lua_code += std::to_string(_value);
            _lua_code += " ) then return \"Element ";
            _lua_code += _element;
            _lua_code += " is lower than threshold";
            _lua_code += "\", ";
            _lua_code += std::to_string(_value);
            _lua_code += ", \"IS\" else return \"\", ";
            _lua_code += std::to_string(_value);
            _lua_code += " , \"ISNT\" end";
        }
        else
        {
            _lua_code = "if ( ";
            _lua_code += _metric;
            _lua_code += "_";
            _lua_code += _element;
            _lua_code += " >  ";
            _lua_code += std::to_string(_value);
            _lua_code += " ) then return \"Element ";
            _lua_code += _element;
            _lua_code += " is higher than threshold";
            _lua_code += "\", ";
            _lua_code += std::to_string(_value);
            _lua_code += ", \"IS\" else return \"\", ";
            _lua_code += std::to_string(_value);
            _lua_code += " , \"ISNT\" end";
        }
        zsys_info ("generated_lua = %s", _lua_code.c_str());
    };

    void generateNeededTopic (void)
    {
        // it is bad to open the notion, how topic is formed, but for now there is now better place
        _in = _metric + "@" + _element;
    };

    lua_State* setContext (const MetricList &metricList) const
    {
        lua_State *lua_context = lua_open();
        double neededValue = metricList.find (_in);
        if ( isnan (neededValue) ) {
            zsys_info("Do not have everything for '%s' yet\n", _rule_name.c_str());
            lua_close (lua_context);
            return NULL;
        }
        std::string var = _metric + "_" + _element;
        zsys_info("Setting variable '%s' to %lf\n", var.c_str(), neededValue);
        lua_pushnumber (lua_context, neededValue);
        lua_setglobal (lua_context, var.c_str());
        return lua_context;
    };

private:
    std::string _metric;
    std::string _type;
    double _value;
    // this field is generated field
    std::string _in;
};

#endif // SRC_THRESHOLDRULE_H
