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

/// @file regexrule.h
/// @author Alena Chernikava <AlenaChernikava@Eaton.com>
/// @brief Representation of PATTERN rule

#pragma once

#include "luarule.h"
#include <czmq.h> //zrex

class RegexRule final : public LuaRule
{
public:
    RegexRule() {}
    ~RegexRule() { zrex_destroy(&_rex); }

    virtual std::string clazz() const { return LuaRule::clazz() + "/RegexRule"; }

    virtual std::string whoami() const { return "pattern"; }

    virtual int fill(const cxxtools::SerializationInfo& si);

    /// returns 0 if ok (pureAlert initialized)
    virtual int evaluate(const MetricList& metricList, PureAlert& pureAlert);

    virtual bool isTopicInteresting(const std::string& topic) const;

    virtual std::vector<std::string> getNeededTopics() const;

private:
    zrex_t* _rex{nullptr};
    std::string _rex_str;
};
