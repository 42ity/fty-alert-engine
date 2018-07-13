/*
Copyright (C) 2014 - 2017 Eaton

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
 *  \file thresholdrulesimple.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Simple threshold rule representation
 */
#ifndef SRC_THRESHOLDRULESIMPLE_H
#define SRC_THRESHOLDRULESIMPLE_H

#include <fty_log.h>
#include <cxxtools/serializationinfo.h>

#include "rule.h"

class ThresholdRuleSimple : public Rule
{
public:

    ThresholdRuleSimple(){};

    std::string whoami () const { return "threshold"; }

    // throws -> it is simple threshold but with errors
    // 0 - ok
    // 1 - it is not simple threshold rule
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
        if ( _rule_source != "Manual user input" ) {
            return 1;
        }
        log_debug ("it is simple threshold rule");

        si_getValueUtf8 (threshold, "target", _metric);
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

    int evaluate (const MetricList &metricList, PureAlert &pureAlert) {
        // ASSUMPTION: constants are in values
        //  high_critical
        //  high_warning
        //  low_warning
        //  low_critical
        const auto GV = getGlobalVariables();
        auto valueToCheck = GV.find ("high_critical");
        if ( valueToCheck != GV.cend() ) {
            if ( valueToCheck->second < metricList.getLastMetric().getValue() ) {
                auto outcome = _outcomes.find ("high_critical");
                pureAlert = PureAlert(ALERT_START, metricList.getLastMetric().getTimestamp() , outcome->second._description, this->_element, this->_rule_class);
                pureAlert._severity = outcome->second._severity;
                pureAlert._actions = outcome->second._actions;
                return 0;
            }
        }
        valueToCheck = GV.find ("high_warning");
        if ( valueToCheck != GV.cend() ) {
            if ( valueToCheck->second < metricList.getLastMetric().getValue() ) {
                auto outcome = _outcomes.find ("high_warning");
                pureAlert = PureAlert(ALERT_START, metricList.getLastMetric().getTimestamp() , outcome->second._description, this->_element, this->_rule_class);
                pureAlert._severity = outcome->second._severity;
                pureAlert._actions = outcome->second._actions;
                return 0;
            }
        }
        valueToCheck = GV.find ("low_critical");
        if ( valueToCheck != GV.cend() ) {
            if ( valueToCheck->second > metricList.getLastMetric().getValue() ) {
                auto outcome = _outcomes.find ("low_critical");
                pureAlert = PureAlert(ALERT_START, metricList.getLastMetric().getTimestamp() , outcome->second._description, this->_element, this->_rule_class);
                pureAlert._severity = outcome->second._severity;
                pureAlert._actions = outcome->second._actions;
                return 0;
            }
        }
        valueToCheck = GV.find ("low_warning");
        if ( valueToCheck != GV.cend() ) {
            if ( valueToCheck->second > metricList.getLastMetric().getValue() ) {
                auto outcome = _outcomes.find ("low_warning");
                pureAlert = PureAlert(ALERT_START, metricList.getLastMetric().getTimestamp() , outcome->second._description, this->_element, this->_rule_class);
                pureAlert._severity = outcome->second._severity;
                pureAlert._actions = outcome->second._actions;
                return 0;
            }
        }
        // if we are here -> no alert was detected
        // TODO actions
        pureAlert = PureAlert(ALERT_RESOLVED, metricList.getLastMetric().getTimestamp(), "ok", this->_element, this->_rule_class);
        pureAlert.print();
        return 0;
    };

    bool isTopicInteresting(const std::string &topic) const {
        return ( _metric == topic ? true : false );
    };

    std::vector<std::string> getNeededTopics(void) const {
        return {_metric};
    };

private:
    // needed metric topic
    std::string _metric;
};


#endif // SRC_THRESHOLDRULESIMPLE_H
