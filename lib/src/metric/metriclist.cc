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

void MetricList::addMetric(const MetricInfo& metric)
{
    const std::string topic{metric.topic()};
    const auto& it = _metrics.find(topic);
    if (it != _metrics.cend()) {
        it->second = metric; // update
    }
    else {
        _metrics[topic] = metric; // add
    }

    _lastAdded = metric;
}

MetricInfo MetricList::lastMetric() const
{
    return _lastAdded;
}

MetricInfo MetricList::getMetric(const std::string& topic) const
{
    const auto& it = _metrics.find(topic);
    return (it != _metrics.cend()) ? it->second : MetricInfo();
}

double MetricList::find(const std::string& topic) const
{
    const auto& it = _metrics.find(topic);
    return (it != _metrics.cend()) ? it->second._value : std::nan("");
}

void MetricList::cleanupOutdatedMetrics()
{
    uint64_t now{static_cast<uint64_t>(::time(NULL))};

    for (auto it = _metrics.cbegin(); it != _metrics.cend(); /*empty*/) {
        if ((now - it->second._timestamp) > it->second._ttl) {
            _metrics.erase(it++); // erase outdated metric
        }
        else {
            ++it;
        }
    }
}
