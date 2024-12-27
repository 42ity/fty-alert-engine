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

/// @file thresholdruledevice.h
/// @author Alena Chernikava <AlenaChernikava@Eaton.com>
/// @brief Threshold rule representation for rules directly extracted from device
#pragma once

#include "rule.h"
#include "audit_log.h"
#include <fty/expected.h>
#include <cxxtools/serializationinfo.h>

class ThresholdRuleDevice : public Rule
{
public:
    ThresholdRuleDevice() {}

    std::string whoami() const
    {
        return "threshold";
    }

    // throws -> it is device threshold but with errors
    // 0 - ok
    // 1 - it is not device threshold rule
    int fill(const cxxtools::SerializationInfo& si)
    {
        _si = si;
        if (si.findMember("threshold") == NULL) {
            return 1;
        }
        auto threshold = si.getMember("threshold");
        if (threshold.category() != cxxtools::SerializationInfo::Object) {
            log_error("Root of json must be an object with property 'threshold'.");
            throw std::runtime_error("Root of json must be an object with property 'threshold'.");
        }

        // target
        auto target = threshold.getMember("target");
        if (target.category() != cxxtools::SerializationInfo::Value) {
            return 1;
        }
        std::string value;
        target >>= value;
        _metrics.push_back(value);

        // rule_source
        if (threshold.findMember("rule_source") == NULL) {
            // if key is not there, take default
            _rule_source = "Manual user input";
            threshold.addMember("rule_source") <<= _rule_source;
        } else {
            auto rule_source = threshold.getMember("rule_source");
            if (rule_source.category() != cxxtools::SerializationInfo::Value) {
                throw std::runtime_error("'rule_source' in json must be value.");
            }
            rule_source >>= _rule_source;
        }
        log_debug("rule_source = %s", _rule_source.c_str());
        if (_rule_source == "Manual user input") {
            return 1;
        }
        log_debug("it is device threshold rule");

        si_getValueUtf8(threshold, "rule_name", _name);
        si_getValueUtf8(threshold, "element", _element);

        // rule_class
        if (threshold.findMember("rule_class") != NULL) {
            threshold.getMember("rule_class") >>= _rule_class;
        }
        // values
        // TODO check low_critical < low_warning < high_warning < hign crtical
        std::map<std::string, double> tmp_values;
        auto values = threshold.getMember("values");
        if (values.category() != cxxtools::SerializationInfo::Array) {
            log_error("parameter 'values' in json must be an array.");
            throw std::runtime_error("parameter 'values' in json must be an array");
        }
        values >>= tmp_values;
        globalVariables(tmp_values);

        // outcomes
        auto outcomes = threshold.getMember("results");
        if (outcomes.category() != cxxtools::SerializationInfo::Array) {
            log_error("parameter 'results' in json must be an array.");
            throw std::runtime_error("parameter 'results' in json must be an array.");
        }
        outcomes >>= _outcomes;
        return 0;
    }

    int evaluate(const MetricList& metricList, PureAlert& pureAlert)
    {
        // ASSUMPTION: constants are in values
        //  high_critical
        //  high_warning
        //  low_warning
        //  low_critical

        log_debug("ThresholdRuleSimple::evaluate %s", _name.c_str());

    #if 0 //DBG, trace _outcomes
        log_debug("%s: outcomes (size: %zu)", _name.c_str(), _outcomes.size());
        for (auto& outcome : _outcomes) {
            log_debug("%s: %s", outcome.first.c_str(), outcome.second.str().c_str());
        }
    #endif

        const auto GV = getGlobalVariables();
        const MetricInfo lastMetric = metricList.getLastMetric();

        auto valueToCheck = GV.find("high_critical");
        if (valueToCheck != GV.cend()) {
            if (valueToCheck->second < lastMetric.getValue()) {
                auto outcome = _outcomes.find("high_critical");
                if (outcome == _outcomes.cend()) {
                    log_error("%s: outcome high_critical is missing", _name.c_str());
                }
                else {
                    pureAlert           = PureAlert(ALERT_START, lastMetric.getTimestamp(),
                        outcome->second._description, this->_element, this->_rule_class);
                    pureAlert._severity = outcome->second._severity;
                    pureAlert._actions  = outcome->second._actions;

                    log_audit_alarm(lastMetric, pureAlert);
                    return 0;
                }
            }
        }

        valueToCheck = GV.find("high_warning");
        if (valueToCheck != GV.cend()) {
            if (valueToCheck->second < lastMetric.getValue()) {
                auto outcome = _outcomes.find("high_warning");
                if (outcome == _outcomes.cend()) {
                    log_error("%s: outcome high_warning is missing", _name.c_str());
                }
                else {
                    pureAlert           = PureAlert(ALERT_START, lastMetric.getTimestamp(),
                        outcome->second._description, this->_element, this->_rule_class);
                    pureAlert._severity = outcome->second._severity;
                    pureAlert._actions  = outcome->second._actions;

                    log_audit_alarm(lastMetric, pureAlert);
                    return 0;
                }
            }
        }

        valueToCheck = GV.find("low_critical");
        if (valueToCheck != GV.cend()) {
            if (valueToCheck->second > lastMetric.getValue()) {
                auto outcome = _outcomes.find("low_critical");
                if (outcome == _outcomes.cend()) {
                    log_error("%s: outcome low_critical is missing", _name.c_str());
                }
                else {
                    pureAlert           = PureAlert(ALERT_START, lastMetric.getTimestamp(),
                        outcome->second._description, this->_element, this->_rule_class);
                    pureAlert._severity = outcome->second._severity;
                    pureAlert._actions  = outcome->second._actions;

                    log_audit_alarm(lastMetric, pureAlert);
                    return 0;
                }
            }
        }

        valueToCheck = GV.find("low_warning");
        if (valueToCheck != GV.cend()) {
            if (valueToCheck->second > lastMetric.getValue()) {
                auto outcome = _outcomes.find("low_warning");
                if (outcome == _outcomes.cend()) {
                    log_error("%s: outcome low_warning is missing", _name.c_str());
                }
                else {
                    pureAlert           = PureAlert(ALERT_START, lastMetric.getTimestamp(),
                        outcome->second._description, this->_element, this->_rule_class);
                    pureAlert._severity = outcome->second._severity;
                    pureAlert._actions  = outcome->second._actions;

                    log_audit_alarm(lastMetric, pureAlert);
                    return 0;
                }
            }
        }

        // if we are here -> no alert was detected
        // TODO actions
        pureAlert = PureAlert(ALERT_RESOLVED, lastMetric.getTimestamp(), "ok", this->_element, this->_rule_class);

        log_audit_alarm(lastMetric, pureAlert);
        return 0;
    }

private:
    // log alarm audit
    void log_audit_alarm(const MetricInfo& metric, const PureAlert& pureAlert) const
    {
        std::string auditValues = metric.getSource() + "=" + std::to_string(metric.getValue());

        std::string auditDesc =
            (pureAlert._status == ALERT_RESOLVED) ? ALERT_RESOLVED : // RESOLVED
            std::string{pureAlert._status + "/" + pureAlert._severity.substr(0, 1)}; // ACTIVE/C ACTIVE/W

        audit_log_info("%8s %s (%s)", auditDesc.c_str(), _name.c_str(), auditValues.c_str());
    }
};
