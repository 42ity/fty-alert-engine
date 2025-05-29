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
#include <cxxtools/serializationinfo.h>

class ThresholdRuleSimple : public Rule
{
public:
    ThresholdRuleSimple() {};

    std::string whoami() const
    {
        return "threshold";
    }

    virtual int fill(const cxxtools::SerializationInfo& si);

    virtual int evaluate(const MetricList& metricList, PureAlert& pureAlert);

    bool isTopicInteresting(const std::string& topic) const
    {
        return (_metric == topic);
    }

    std::vector<std::string> getNeededTopics(void) const
    {
        return {_metric};
    }

private:
    void log_audit_alarm(const MetricInfo& metric, const PureAlert& pureAlert) const;

    // needed metric topic
    std::string _metric;
};
