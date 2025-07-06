/*
 * Copyright (C) 2014 - 2020 Eaton
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

/// @file matcher.h
/// @brief rule matcher interfaces

#pragma once

#include "rule.h" //RulePtr
#include <string>

class RuleMatcher
{
public:
    virtual bool match(const RulePtr& rule) const = 0;

protected:
    virtual ~RuleMatcher() = default;
};

/// Rule has same name as
class RuleNameMatcher : public RuleMatcher
{
public:
    RuleNameMatcher(const std::string& name);
    bool match(const RulePtr& rule) const override;

private:
    std::string _name;
};

/// Rule has same element as
class RuleElementMatcher : public RuleMatcher
{
public:
    RuleElementMatcher(const std::string& element);
    bool match(const RulePtr& rule) const override;

private:
    std::string _element;
};
