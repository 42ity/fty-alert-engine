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

/*! \file metricinfo.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Very simple class to store information about one metric
 */
#pragma once
#include <string>

class MetricInfo
{

public:
    std::string generateTopic(void) const
    {
        return _source + "@" + _element_name;
    };

    MetricInfo()
        : _value{0}
        , _timestamp{0}
        , _ttl{5 * 60} {};

    MetricInfo(const std::string& element_name, const std::string& source, const std::string& units, double value,
        uint64_t timestamp, const std::string& destination, uint64_t ttl)
        : _element_name(element_name)
        , _source(source)
        , _units(units)
        , _value(value)
        , _timestamp(timestamp)
        , _element_destination_name(destination)
        , _ttl(ttl){};

    double getValue(void) const
    {
        return _value;
    };

    std::string getElementName(void) const
    {
        return _element_name;
    };

    uint64_t getTimestamp(void) const
    {
        return _timestamp;
    };

    bool isUnknown(void) const
    {
        if (_element_name.empty() || _source.empty() || _units.empty()) {
            return true;
        }
        return false;
    };

    uint64_t getTtl(void) const
    {
        return _ttl;
    };

    std::string getUnits(void) const
    {
        return _units;
    };

    std::string getSource(void) const
    {
        return _source;
    };
    void setTime(void)
    {
        _timestamp = static_cast<uint64_t>(::time(NULL));
    };
    void setUnits(const std::string& U)
    {
        _units = U;
    };
    friend inline bool operator==(const MetricInfo& lhs, const MetricInfo& rhs);
    friend inline bool operator!=(const MetricInfo& lhs, const MetricInfo& rhs);

    // This class is very close to metric info
    // So let it use fields directly
    friend class MetricList;

private:
    std::string _element_name;
    std::string _source;
    std::string _units;
    double      _value;
    uint64_t    _timestamp;
    std::string _element_destination_name;

    // time to live [s]
    uint64_t _ttl;
};

inline bool operator==(const MetricInfo& lhs, const MetricInfo& rhs)
{
    return (lhs._units == rhs._units && lhs._value == rhs._value);
}

inline bool operator!=(const MetricInfo& lhs, const MetricInfo& rhs)
{
    return !(lhs == rhs);
}
