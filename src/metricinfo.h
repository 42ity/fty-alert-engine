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

/*! \file metricinfo.cc
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Very simple class to store information about one metric
 */

#include <string>

class MetricInfo {

public:
    std::string generateTopic(void) const {
        return _source + "@" + _element_name;
    };

    MetricInfo() {
        _timestamp = 0;
    };

    MetricInfo (
        const std::string &element_name,
        const std::string &source,
        const std::string &units,
        double value,
        int64_t timestamp,
        const std::string &destination
        ):
        _element_name (element_name),
        _source (source),
        _units (units),
        _value (value),
        _timestamp (timestamp),
        _element_destination_name (destination)
    {};

    double getValue (void) {
        return _value;
    };

    std::string getElementName (void) {
        return _element_name;
    };

    int64_t getTimestamp (void) const {
        return _timestamp;
    };

    bool isUnknown() const {
        if ( _element_name.empty() ||
             _source.empty() ||
             _units.empty() ) {
            return true;
        }
        return false;
    };

    // This class is very close to metric info
    // So let it use fields directly
    friend class MetricList;

private:
    std::string _element_name;
    std::string _source;
    std::string _units;
    double      _value;
    int64_t     _timestamp;
    std::string _element_destination_name;

};
