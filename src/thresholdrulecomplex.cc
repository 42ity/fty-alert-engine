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

/*!
 *  \file thresholdrulecomplex.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Complex threshold rule representation
 */

#include <czmq.h>
#include <sstream>

#include "thresholdrulecomplex.h"

int ThresholdRuleComplex::
    fill(
        cxxtools::JsonDeserializer &json)
{
    const cxxtools::SerializationInfo *si = json.si();
    if ( si->findMember("threshold") == NULL ) {
        return 1;
    }
    auto threshold = si->getMember("threshold");
    if ( threshold.category () != cxxtools::SerializationInfo::Object ) {
        zsys_info ("Root of json must be an object with property 'threshold'.");
        throw std::runtime_error("Root of json must be an object with property 'threshold'.");
    }

    // target
    auto target = threshold.getMember("target");
    if ( target.category () != cxxtools::SerializationInfo::Array ) {
        return 1;
    }
    zsys_info ("it is complex threshold rule");

    target >>= _metrics;
    
    // serialize to json, so we have actual json without the trash
    std::stringstream output_json;
    cxxtools::JsonSerializer serializer(output_json);
    serializer.beautify(false);   // not so nice to read, but very compact
    serializer.serialize((*si));
    output_json >> _json_representation;

    threshold.getMember("rule_name") >>= _name;
    threshold.getMember("element") >>= _element;
    // values
    // TODO check low_critical < low_warning < high_warning < high_critical
    std::map<std::string,double> tmp_values;
    auto values = threshold.getMember("values");
    if ( values.category () != cxxtools::SerializationInfo::Array ) {
        zsys_info ("parameter 'values' in json must be an array.");
        throw std::runtime_error("parameter 'values' in json must be an array");
    }
    values >>= tmp_values;
    globalVariables(tmp_values);

    // outcomes
    auto outcomes = threshold.getMember("results");
    if ( outcomes.category () != cxxtools::SerializationInfo::Array ) {
        zsys_info ("parameter 'results' in json must be an array.");
        throw std::runtime_error ("parameter 'results' in json must be an array.");
    }
    outcomes >>= _outcomes;

    std::string tmp;
    threshold.getMember("evaluation") >>= tmp;
    try {
        code(tmp);
    }
    catch ( const std::exception &e ) {
        zsys_warning ("something with lua function: %s", e.what());
        return 2;
    }

    return 0;
}

