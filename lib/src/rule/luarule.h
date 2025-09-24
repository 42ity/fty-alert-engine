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

/*! \file luaRule.h
 *  \author Tomas Halman <TomasHalman@eaton.com>
 *  \brief Class implementing Lua rule evaluation
 */

#pragma once

#include "rule.h"

#include <lua.hpp>
#include <string>
#include <map>

class LuaRule : public Rule
{
public:
    LuaRule() {}
    LuaRule(const LuaRule& r);
    ~LuaRule();

    virtual std::string clazz() const { return Rule::clazz() + "/LuaRule"; }

    virtual void globalVariables(const std::map<std::string, double>& variables);

    /// returns 0 if ok (pureAlert initialized)
    virtual int evaluate(const MetricList& metricList, PureAlert& pureAlert);

    /// get/set Lua code
    std::string code() const { return _code; }
    void code(const std::string& code); // throw on error

private:
    void luaSetGlobalVariables();
    double luaEvaluate(const std::vector<double>& arguments);

    bool _valid{false};
    lua_State* _lstate{nullptr};
    std::string _code; // Lua
};
