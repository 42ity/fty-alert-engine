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

#include "thresholdruledevice.h"
#include "misc/audit_log.h"
#include "misc/json.h"

#include <fty_log.h>

int ThresholdRuleDevice::fill(const cxxtools::SerializationInfo& si)
{
    _si = si;

    // *must* threshold root object
    const std::string rootName{"threshold"};
    auto root{JSON::findMember(si, rootName)};
    if (!root) {
        return 1; // not recognized
    }
    if (!JSON::isObject(root)) {
        const std::string err{"Object member expected (" + rootName + ")"};
        log_error("%s", err.c_str());
        throw std::runtime_error(err);
    }

    // *must* target defined as value
    auto target{JSON::findMember(root, "target")};
    if (!JSON::isValue(target)) {
        return 1; // not recognized
    }
    _metrics.push_back(JSON::getString(target)); // singleton

    // *must* rule_source not the default
    std::string _rule_source = JSON::getString(JSON::findMember(root, "rule_source"));
    if (_rule_source.empty() || (_rule_source == RULE_SOURCE_DEFAULT)) {
        log_debug("rule_source = %s", _rule_source.c_str());
        return 1; // not recognized
    }

    log_debug("Rule class: %s, root: %s)", clazz().c_str(), rootName.c_str());

    _name = JSON::getStringUtf8(JSON::findMember(root, "rule_name"));
    _element = JSON::getStringUtf8(JSON::findMember(root, "element"));
    _rule_class = JSON::getString(JSON::findMember(root, "rule_class"));

    // outcomes
    _outcomes = JSON::getMapOutcome(JSON::findMember(root, "results"));

    // values (TODO: check low_critical<low_warning<high_warning<high_critical)
    globalVariables(JSON::getMapDouble(JSON::findMember(root, "values")));

    return 0; // recognized and initialized correctly
}

/// returns 0 if ok (pureAlert initialized)
int ThresholdRuleDevice::evaluate(const MetricList& metricList, PureAlert& pureAlert)
{
    log_debug("ThresholdRuleDevice::evaluate %s", _name.c_str());

    // outcome tokens
    static const std::string LC_TOKEN{outcome::resultToString(outcome::RULE_RESULT_LOW_CRITICAL)};
    static const std::string LW_TOKEN{outcome::resultToString(outcome::RULE_RESULT_LOW_WARNING)};
    static const std::string HW_TOKEN{outcome::resultToString(outcome::RULE_RESULT_HIGH_WARNING)};
    static const std::string HC_TOKEN{outcome::resultToString(outcome::RULE_RESULT_HIGH_CRITICAL)};

    const auto GV = globalVariables();
    const MetricInfo lastMetric = metricList.getLastMetric();

    auto checkThreshold = [this, &GV, &lastMetric, &pureAlert] (const std::string& TOKEN, bool ltCond) {
        auto threshold = GV.find(TOKEN);
        if (threshold != GV.cend()) {
            auto metricValue = lastMetric.getValue();
            auto thresholdValue = threshold->second;
            if (    (!ltCond && (metricValue > thresholdValue)) // higher than
                 || ( ltCond && (metricValue < thresholdValue)) // lower than
            ) {
                const auto outcome = _outcomes.find(TOKEN);
                if (outcome != _outcomes.cend()) {
                    pureAlert = PureAlert(ALERT_START, lastMetric.getTimestamp(), outcome->second._description, _element, _rule_class);
                    pureAlert._severity = outcome->second._severity;
                    pureAlert._actions  = outcome->second._actions;
                    return true; // ALERT_START
                }
                else {
                    log_error("%s: outcome %s is missing", _name.c_str(), TOKEN.c_str());
                }
            }
        }
        return false;
    };

    // in order
    if (   !checkThreshold(HC_TOKEN, false) // higher than
        && !checkThreshold(HW_TOKEN, false)
        && !checkThreshold(LC_TOKEN, true ) // lower than
        && !checkThreshold(LW_TOKEN, true )
    ) {
        // if we are here -> no alert was detected (TODO actions)
        const std::string descr{"ok"};
        pureAlert = PureAlert(ALERT_RESOLVED, lastMetric.getTimestamp(), descr, _element, _rule_class);
    }

    log_audit_alarm(lastMetric, pureAlert);
    return 0;
}

// log alarm audit
void ThresholdRuleDevice::log_audit_alarm(const MetricInfo& metric, const PureAlert& pureAlert) const
{
    std::string auditValues = metric.getType() + "=" + std::to_string(metric.getValue());

    std::string auditDesc =
        (pureAlert._status == ALERT_RESOLVED) ? ALERT_RESOLVED : // RESOLVED
        std::string{pureAlert._status + "/" + pureAlert._severity.substr(0, 1)}; // ACTIVE/C ACTIVE/W

    audit_log_info("%8s %s (%s)", auditDesc.c_str(), _name.c_str(), auditValues.c_str());
}

