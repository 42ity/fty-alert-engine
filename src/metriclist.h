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

/*! \file metriclist.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief This class is intended to handle set of current known metrics
 */
#ifndef SRC_METRICLIST_H
#define SRC_METRICLIST_H

#include <string>
#include <map>

#include "metricinfo.h"

/*
 * \brief This class is intended to handle set of current known metrics.
 *
 * You can create it, ad new metrics, find known metrics by topic,
 * and remove metrics that are not valid.
 */
class MetricList {
public:

    /*
     * \brief Constrocts the empty list
     */
    MetricList() {};

    /*
     * \brief Destroys the list
     */
    ~MetricList() {};

    /*
     * \brief Adds new metric
     *
     * This will add new metric if it isn't known to the list
     * and update the value if it is known already.
     *
     * Also it will update value of last added Metric.
     *
     * \param[in] metricInfo - metric to add
     */
    void addMetric (const MetricInfo &metricInfo);

    /*
     * \brief Finds a value of the metric in the list and checks if
     *        it is still valid.
     *
     * This method doesn't remove metric from the list if it is too old.
     * To check is value is NAN or not use isnan() function from math.h
     *
     * \param[in] topic - topic we are looking for
     *
     * \return NAN   - if metric is too old or
     *                  it is not present in the list
     *         value - otherwise
     */
    double findAndCheck (const std::string &topic) const;

    /*
     * \brief Finds a value of the metric in the list
     *
     * To check is value is NAN or not use isnan() function from math.h
     *
     * \param[in] topic - topic we are looking for
     *
     * \return NAN   - if metric is not present in the list
     *         value - otherwise
     */
    double find (const std::string &topic) const;

    /*
     * \brief Gets metric by the topic
     *
     * \param[in] topic - topic we are looking for
     *
     * \return MetricInfo       - if metric was found or
     *         MetricInfo empty - if metric isn't found
     *                            ( isUnknown() is true)
     */
    MetricInfo getMetricInfo (
        const std::string &topic) const;

    /*
     * \brief Removes old metrics from the list
     */
    void removeOldMetrics (void);

    /*
     * \brief Gets the last added metric
     *
     * \return last added (or updated) metric
     */
    MetricInfo getLastMetric (void) const {
        return _lastInsertedMetric;
    };

private:

    // Metric list <topic, Metric>
    std::map <std::string, MetricInfo> _knownMetrics;

    // Keep track of last inserted metric
    MetricInfo _lastInsertedMetric;
};

void
metriclist_test (bool verbose);
#endif // SRC_METRICLIST_H_
