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

class RegexRule : public LuaRule
{
public:
    RegexRule() {}
    ~RegexRule() { zrex_destroy(&_rex); }

    std::string whoami() const { return "pattern"; }

    /// parse json and check lua and fill the object
    ///
    /// ATTENTION: throws, if bad JSON
    ///
    /// @return 1 if rule has other type
    ///         2 if lua function has errors
    ///         0 if everything is ok
    virtual int fill(const cxxtools::SerializationInfo& si);

    /// returns 0 if ok
    virtual int evaluate(const MetricList& metricList, PureAlert& pureAlert);

    bool isTopicInteresting(const std::string& topic) const;

    std::vector<std::string> getNeededTopics() const;

private:
    zrex_t* _rex{nullptr};
    std::string _rex_str;
};
