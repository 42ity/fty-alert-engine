/*
Copyright (C) 2014 - 2019 Eaton

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
#include <lua.h>
}

class LuaRule : public Rule {
 public:
    /**
     * \brief set the evaluation code
     */
    LuaRule () {};
    LuaRule (const LuaRule &r);
    void code (const std::string &newCode);
    std::string code () const { return _code; };
    void globalVariables (const std::map<std::string,double> &vars);
    int evaluate (const MetricList &metricList, PureAlert &pureAlert);
    double luaEvaluate(const std::vector<double> &metrics);
    ~LuaRule ();
 protected:
    void _setGlobalVariablesToLUA();

    bool _valid = false;
    lua_State *_lstate = NULL;
 private:
    std::string _code;
};

#endif // __include_luaRule__
