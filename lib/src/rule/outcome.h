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

#pragma once

#include <string>
#include <vector>

namespace outcome
{
    enum RULE_RESULT
    {
        RULE_RESULT_LOW_CRITICAL  = -2,
        RULE_RESULT_LOW_WARNING   = -1,
        RULE_RESULT_OK            = 0,
        RULE_RESULT_HIGH_WARNING  = 1,
        RULE_RESULT_HIGH_CRITICAL = 2,
        RULE_RESULT_UNKNOWN       = 3,
    };

    // num. <-> token converter
    std::string resultToString(int result);
    int resultToInt(const std::string& result);
} /// namespace

/// Helper structure to store a possible outcome of rule evaluation
/// Rule evaluation outcome has three values:
/// - actions
/// - description
/// - severity // severity is detected automatically; user cannot set it

struct Outcome
{
    std::vector<std::string> _actions;
    std::string              _description;
    std::string              _severity;

    //dbg
    std::string str();
};
