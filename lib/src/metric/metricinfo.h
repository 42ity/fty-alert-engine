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

/// @file metricinfo.h
/// @author Alena Chernikava <AlenaChernikava@Eaton.com>
/// @brief Class to store information about one metric

#pragma once

#include <string>
#include <cstdint>

class MetricInfo
{
public:
    MetricInfo() = default;

    MetricInfo(
        const std::string& element_name,
        const std::string& source,
        double value,
        uint64_t timestamp,
        uint64_t ttl
    )
        : _element_name(element_name) // asset iname
        , _source(source) // metric type
        , _value(value)
        , _timestamp(timestamp)
        , _ttl(ttl)
    {}

    /// accessors
    std::string getElementName() const { return _element_name; }
    std::string getSource() const { return _source; }
    double getValue() const { return _value; }
    uint64_t getTimestamp() const { return _timestamp; }
    uint64_t getTtl() const { return _ttl; }

    /// topic name (built)
    std::string generateTopic() const
    {
        return _source + "@" + _element_name; // <metric type>@<asset iname>
    }

    friend class MetricList;

private:
    std::string _element_name; /// asset iname
    std::string _source; /// metric type
    double      _value{0};
    uint64_t    _timestamp{0}; /// latest update (epoch time, sec.)
    uint64_t    _ttl{0}; /// time to live (sec)
};
