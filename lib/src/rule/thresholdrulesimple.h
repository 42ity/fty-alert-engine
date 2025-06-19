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

/// @file thresholdrulesimple.h
/// @author Alena Chernikava <AlenaChernikava@Eaton.com>
/// @brief Simple threshold rule representation

#pragma once

#include "rule.h"

class ThresholdRuleSimple final : public Rule
{
public:
    ThresholdRuleSimple() {}

    virtual std::string clazz() const { return Rule::clazz() + "/ThresholdRuleSimple"; }

    virtual std::string whoami() const { return "threshold"; }

    virtual int fill(const cxxtools::SerializationInfo& si);

    /// returns 0 if ok (pureAlert initialized)
    virtual int evaluate(const MetricList& metricList, PureAlert& pureAlert);

private:
    void log_audit_alarm(const MetricInfo& metric, const PureAlert& pureAlert) const;
};
