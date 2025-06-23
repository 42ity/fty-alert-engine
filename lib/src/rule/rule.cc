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

#include "rule.h"
#include "misc/utils.h"

#include <fty_common_json.h>
#include <fty_log.h>

bool Rule::isTopicInteresting(const std::string& topic) const
{
    for (const auto& it : _metrics) {
        if (it == topic)
            { return true; }
    }
    return false;
}

std::vector<std::string> Rule::getNeededTopics() const
{
    return _metrics;
}

/// Gets a json representation of the rule
/// @return json payload
std::string Rule::json() const noexcept
{
    try {
        return JSON::writeToString(_si, true);
    }
    catch (const std::exception& e) {
        log_error("json parser exception (%s, e: %s)", _name.c_str(), e.what());
    }
    return "{}";
}

/// Save rule to the persistance
/// assume path with / term
void Rule::save(const std::string& path, const std::string& name) const noexcept
{
    try {
        const std::string full_name{path + name};
        JSON::writeToFile(full_name, _si, true);
    }
    catch (const std::exception& e) {
        log_error("save() failed (%s, e: %s)", _name.c_str(), e.what());
    }
}

/// Delete rule from the persistance
/// @param[in] path - a path to files (assume / term)
/// @return 0 on success, non-zero on error
int Rule::remove(const std::string& path) const noexcept
{
    const std::string full_name{path + _name + ".rule"};
    log_debug("remove file '%s'", full_name.c_str());
    return std::remove(full_name.c_str());
}

///
/// Rule matchers
///

RuleNameMatcher::RuleNameMatcher(const std::string& name) : _name(name) {}

bool RuleNameMatcher::operator()(const Rule& rule)
{
    return rule.name() == _name;
}

RuleElementMatcher::RuleElementMatcher(const std::string& element) : _element(element) {}

bool RuleElementMatcher::operator()(const Rule& rule)
{
    return rule.element() == _element;
}
