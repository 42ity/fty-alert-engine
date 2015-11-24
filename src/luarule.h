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

/*! \file luaRule.h
 *  \author Tomas Halman <TomasHalman@eaton.com>
 *  \brief Class implementing Lua rule evaluation
 */

#ifndef __include_luaRule__
#define __include_luaRule__

#include "rule.h"
extern "C" {
#include<lua.h>
}

enum RULE_RESULT {
    RULE_RESULT_TO_LOW_CRITICAL = -2,
    RULE_RESULT_TO_LOW_WARNING  = -1,
    RULE_RESULT_OK              =  0,
    RULE_RESULT_TO_HI_WARNING   =  1,
    RULE_RESULT_TO_HI_CRITICAL  =  2,
};

class LuaRule : public Rule {
 public:
    /**
     * \brief set the evaluation code
     */
    LuaRule () {};
    LuaRule (const LuaRule &r);
    void code (const std::string &newCode);
    std::string code () { return _code; };
    void globalVariables (const std::map<std::string,double> &vars);
    int evaluate (const MetricList &metricList, PureAlert **pureAlert);
    double evaluate(const std::vector<double> &metrics);
    ~LuaRule () { if (_lstate) lua_close (_lstate); }
 protected:
    void _setGlobalVariablesToLUA();
    
    std::string _code;
    bool _valid = false;
    lua_State *_lstate = NULL;
};

#endif // __include_luaRule__
