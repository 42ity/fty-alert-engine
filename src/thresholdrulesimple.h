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
 *  \file thresholdrulesimple.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Simple threshold rule representation
 */
#ifndef SRC_THRESHOLDRULESIMPLE_H
#define SRC_THRESHOLDRULESIMPLE_H

#include "rule.h"

class ThresholdRuleSimple : public Rule
{
public:

    ThresholdRuleSimple(){};

    int evaluate (const MetricList &metricList, PureAlert **pureAlert) {
        // ASSUMPTION: constants are in values
        //  high_critical
        //  high_warning
        //  low_warning
        //  low_critical

        auto valueToCheck = _variables.find ("high_critical");
        if ( valueToCheck != _variables.cend() ) {
            if ( valueToCheck->second < metricList.getLastMetric().getValue() ) {
                auto outcome = _outcomes.find ("high_critical");
                *pureAlert = new PureAlert(ALERT_START, metricList.getLastMetric().getTimestamp() , outcome->second._description, this->_element);
                (*pureAlert)->_severity = outcome->second._severity;
                (*pureAlert)->_actions = outcome->second._actions;
                return 0;
            }
        }
        valueToCheck = _variables.find ("high_warning");
        if ( valueToCheck != _variables.cend() ) {
            if ( valueToCheck->second < metricList.getLastMetric().getValue() ) {
                auto outcome = _outcomes.find ("high_warning");
                *pureAlert = new PureAlert(ALERT_START, metricList.getLastMetric().getTimestamp() , outcome->second._description, this->_element);
                (*pureAlert)->_severity = outcome->second._severity;
                (*pureAlert)->_actions = outcome->second._actions;
                return 0;
            }
        }
        valueToCheck = _variables.find ("low_critical");
        if ( valueToCheck != _variables.cend() ) {
            if ( valueToCheck->second > metricList.getLastMetric().getValue() ) {
                auto outcome = _outcomes.find ("low_critical");
                *pureAlert = new PureAlert(ALERT_START, metricList.getLastMetric().getTimestamp() , outcome->second._description, this->_element);
                (*pureAlert)->_severity = outcome->second._severity;
                (*pureAlert)->_actions = outcome->second._actions;
                return 0;
            }
        }
        valueToCheck = _variables.find ("low_warning");
        if ( valueToCheck != _variables.cend() ) {
            if ( valueToCheck->second > metricList.getLastMetric().getValue() ) {
                auto outcome = _outcomes.find ("low_warning");
                *pureAlert = new PureAlert(ALERT_START, metricList.getLastMetric().getTimestamp() , outcome->second._description, this->_element);
                (*pureAlert)->_severity = outcome->second._severity;
                (*pureAlert)->_actions = outcome->second._actions;
                return 0;
            }
        }
        // if we are here -> no alert was detected
        // TODO actions
        *pureAlert = new PureAlert(ALERT_RESOLVED, metricList.getLastMetric().getTimestamp(), "ok", this->_element);
        (**pureAlert).print();
        return 0;
    };

    bool isTopicInteresting(const std::string &topic) const {
        return ( _metric == topic ? true : false );
    };

    friend Rule* readRule (std::istream &f);

private:
    // needed metric topic
    std::string _metric;
};


#endif // SRC_THRESHOLDRULESIMPLE_H
