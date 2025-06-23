/*
 * Copyright (C) 2014 - 2025 Eaton
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "outcome.h"
#include <string>
#include <map>
#include <sstream>

std::string Outcome::str()
{
    std::ostringstream oss;
    size_t i = 0;
    for (auto& a : _actions)
        { oss << "actions[" << i++ << "](" << a << "),"; }
    oss << "severity(" << _severity << "),"
        << "description(" << _description << ")";

    return oss.str();
}

namespace outcome {

/// outcome RULE_RESULT tokens map
static const std::map<int, std::string> mapTextResults = {
    { RULE_RESULT_LOW_CRITICAL,  "low_critical"  },
    { RULE_RESULT_LOW_WARNING,   "low_warning"   },
    { RULE_RESULT_OK,            "ok"            },
    { RULE_RESULT_HIGH_WARNING,  "high_warning"  },
    { RULE_RESULT_HIGH_CRITICAL, "high_critical" },
    { RULE_RESULT_UNKNOWN,       "unknown"       },
};

/// RULE_RESULT -> token
std::string resultToString(int result)
{
    const auto& it = mapTextResults.find(result);
    if (it != mapTextResults.cend())
        { return it->second; }
    return mapTextResults.find(RULE_RESULT_UNKNOWN)->second;
}

/// token -> RULE_RESULT
int resultToInt(const std::string& result)
{
    for (const auto& it : mapTextResults) {
        if (result == it.second)
            { return it.first; }
    }
    return RULE_RESULT_UNKNOWN;
}

} ///namespace
