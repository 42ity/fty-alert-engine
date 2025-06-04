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

#include "metriclist.h"
#include <cmath>
#include <ctime>

void MetricList::addMetric(const MetricInfo& metricInfo)
{
    // try to find topic
    auto it = _knownMetrics.find(metricInfo.generateTopic());
    if (it != _knownMetrics.cend()) {
        // found -> update
        it->second = metricInfo;
    }
    else {
        // not found -> insert
        _knownMetrics.emplace(metricInfo.generateTopic(), metricInfo);
    }

    _lastInsertedMetric = metricInfo;
}

MetricInfo MetricList::getLastMetric() const
{
    return _lastInsertedMetric;
}

MetricInfo MetricList::getMetricInfo(const std::string& topic) const
{
    const auto& it = _knownMetrics.find(topic);
    return (it != _knownMetrics.cend()) ? it->second : MetricInfo();
}

void MetricList::removeOldMetrics()
{
    uint64_t now = static_cast<uint64_t>(::time(NULL));

    for (auto it = _knownMetrics.cbegin(); it != _knownMetrics.cend(); /*empty*/) {
        if (now > (it->second._timestamp + it->second._ttl)) {
            _knownMetrics.erase(it++); // metric is outdated
        }
        else {
            ++it;
        }
    }
}

double MetricList::findAndCheck(const std::string& topic) const
{
    const auto& it = _knownMetrics.find(topic);
    if (it == _knownMetrics.cend()) {
        return std::nan("");
    }

    uint64_t now = static_cast<uint64_t>(::time(NULL));
    if (now > (it->second._timestamp + it->second._ttl)) {
        return std::nan(""); // metric is outdated
    }

    return it->second._value;
}

double MetricList::find(const std::string& topic) const
{
    const auto& it = _knownMetrics.find(topic);
    return (it != _knownMetrics.cend()) ? it->second._value : std::nan("");
}
