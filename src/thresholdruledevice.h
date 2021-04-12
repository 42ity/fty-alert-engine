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

/*!
 *  \file thresholdruledevice.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Threshold rule representation for rules directly extracted
 *          from device
 */
#ifndef SRC_THRESHOLDRULEDEVICE_H
#define SRC_THRESHOLDRULEDEVICE_H

#include "rule.h"
#include <cxxtools/serializationinfo.h>

class ThresholdRuleDevice : public Rule
{
public:

    ThresholdRuleDevice(){};

    std::string whoami () const { return "threshold"; }

    // throws -> it is device threshold but with errors
    // 0 - ok
    // 1 - it is not device threshold rule
    int fill(const cxxtools::SerializationInfo &si)
    {
        _si = si;
        if ( si.findMember("threshold") == NULL ) {
            return 1;
        }
        auto threshold = si.getMember("threshold");
        if ( threshold.category () != cxxtools::SerializationInfo::Object ) {
            log_error ("Root of json must be an object with property 'threshold'.");
            throw std::runtime_error("Root of json must be an object with property 'threshold'.");
        }

        // target
        auto target = threshold.getMember("target");
        if ( target.category () != cxxtools::SerializationInfo::Value ) {
            return 1;
        }
        // rule_source
        if ( threshold.findMember("rule_source") == NULL ) {
            // if key is not there, take default
            _rule_source = "Manual user input";
            threshold.addMember("rule_source") <<= _rule_source;
        }
        else {
            auto rule_source = threshold.getMember("rule_source");
            if ( rule_source.category () != cxxtools::SerializationInfo::Value ) {
                throw std::runtime_error("'rule_source' in json must be value.");
            }
            rule_source >>= _rule_source;
        }
        log_debug ("rule_source = %s", _rule_source.c_str());
        if ( _rule_source == "Manual user input" ) {
            return 1;
        }
        log_debug ("it is device threshold rule");

        si_getValueUtf8 (threshold, "rule_name", _name);
        si_getValueUtf8 (threshold, "element", _element);

        // rule_class
        if ( threshold.findMember("rule_class") != NULL ) {
            threshold.getMember("rule_class") >>= _rule_class;
        }
        // values
        // TODO check low_critical < low_warnong < high_warning < hign crtical
        std::map<std::string,double> tmp_values;
        auto values = threshold.getMember("values");
        if ( values.category () != cxxtools::SerializationInfo::Array ) {
            log_error ("parameter 'values' in json must be an array.");
            throw std::runtime_error("parameter 'values' in json must be an array");
        }
        values >>= tmp_values;
        globalVariables(tmp_values);

        // outcomes
        auto outcomes = threshold.getMember("results");
        if ( outcomes.category () != cxxtools::SerializationInfo::Array ) {
            log_error ("parameter 'results' in json must be an array.");
            throw std::runtime_error ("parameter 'results' in json must be an array.");
        }
        outcomes >>= _outcomes;
        return 0;
    }

    int evaluate (const MetricList &/* metricList */, PureAlert &/* pureAlert */) {
        // INTENTIONALLY We do not evaluate this rule at all
        // It is evaluated in NUT-agent somewhere
        // rules are here, just to provide webUI access to the rule representation
        return 0;
    };

    bool isTopicInteresting(const std::string &/* topic */) const {
        // we are not interested in any topics
        return false;
    };

    std::vector<std::string> getNeededTopics(void) const {
        return {};
    };
};


#endif // SRC_THRESHOLDRULEDEVICE_H
