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

/// @file metriclist.h
/// @author Alena Chernikava <AlenaChernikava@Eaton.com>
/// @brief This class is intended to handle set of current known metrics

#pragma once

#include "metricinfo.h"
#include <map>
#include <string>

/// This class is intended to handle set of metrics.
///
/// You can create it, add new metrics, find metrics by topic,
/// and remove metrics that are not valid.
class MetricList
{
public:
    /// Constructs the empty list
    MetricList() = default;

    /// Adds new metric
    ///
    /// Add new metric if it isn't known to the list and update the value if it is known already.
    /// Also it will update the last added Metric.
    /// @param[in] metric - metric to add
    void addMetric(const MetricInfo& metric);

    /// Gets the last added metric
    /// @return last added (or updated) metric
    MetricInfo lastMetric() const;

    /// Gets metric by the topic
    /// @param[in] topic - topic we are looking for
    /// @return MetricInfo       - if metric was found or
    ///         MetricInfo empty - if metric isn't found
    MetricInfo getMetric(const std::string& topic) const;

    /// Finds *double* value of the metric in the list
    /// Use std::isnan() (math.h) to check NaN value
    /// @param[in] topic - topic we are looking for
    /// @return NAN if metric was not found
    ///         the value otherwise
    double find(const std::string& topic) const;

    /// Removes outdated metrics from the list
    void cleanupOutdatedMetrics();

private:
    /// Metric list <topic, MetricInfo>
    std::map<std::string, MetricInfo> _metrics;

    /// Keep track of last added metric
    MetricInfo _lastAdded;
};
