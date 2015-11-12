/*
Copyright (C) 2014 - 2015 Eaton

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

// NAN is here
#include <math.h>


void MetricList::
    addMetric (const MetricInfo &metricInfo)
{
    // try to find topic
    auto it = _knownMetrics.find (metricInfo.generateTopic());
    if ( it != _knownMetrics.cend() ) {
        // if it was found -> replace with new value
        it->second = metricInfo;
    }
    else {
        // if it wasn't found -> insert new metric
        _knownMetrics.emplace (metricInfo.generateTopic(), metricInfo);
    }
    _lastInsertedMetric = metricInfo;
};


double MetricList::
    findAndCheck (const std::string &topic) const
{
    auto it = _knownMetrics.find(topic);
    if ( it == _knownMetrics.cend() ) {
        return NAN;
    }
    else {
        int64_t currentTimestamp = ::time(NULL);
        if ( ( currentTimestamp - it->second._timestamp ) > _maxLiveTime ) {
            return NAN;
        }
        else {
            return it->second._value;
        }
    }
};


double MetricList::
    find (const std::string &topic) const
{
    auto it = _knownMetrics.find(topic);
    if ( it == _knownMetrics.cend() ) {
        return NAN;
    }
    else {
        return it->second._value;
    }
};


MetricInfo MetricList::
    getMetricInfo (const std::string &topic) const
{
    auto it = _knownMetrics.find(topic);
    if ( it == _knownMetrics.cend() ) {
        return MetricInfo();
    }
    else {
        return it->second;
    }
};


void MetricList::removeOldMetrics()
{
    int64_t currentTimestamp = ::time(NULL);

    for ( std::map<std::string, MetricInfo>::iterator iter = _knownMetrics.begin(); iter != _knownMetrics.end() ; /* empty */)
    {
        if ( ( currentTimestamp - iter->second._timestamp ) > _maxLiveTime ) {
            _knownMetrics.erase(iter++);
        }
        else {
            ++iter;
        }
    }
};
