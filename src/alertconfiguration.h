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

/*! \file alertconfiguration.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \author Michal Vyskocil  <MichalVyskocil@Eaton.com>
 *  \brief Representation of alert configuration
 */

#ifndef SRC_ALERTCONFIGURATION_H
#define SRC_ALERTCONFIGURATION_H

#include <istream>
#include <string>
#include <set>
#include <vector>
#include <memory>

#include "rule.h"
#include "purealert.h"

/*
 * Parses the input and reads the rule\
 *
 * \param[in]  f    - an input stream to parse a rule
 * \param[out] rule - a parsed rule
 *
 * \return 1 if rule has errors in json
 *         2 if lua function has errors
 *         0 if everything is ok
 */
int readRule (std::istream &f, RulePtr &rule);


// Alert configuration is a class that manages rules and evaruted alerts
//
// ASSUMPTIONS:
//  1. Rules are stored in files. One rule = one file
//  2. File name is a rule name
//  3. Files should have extention ".rule"
//  4. Directory to the files is configurable. Cannot be changed without recompilation
//  5. If rule has at least one mistake or broke any other rule, it is ignored
//  6. Rule name is unique
//
class AlertConfiguration{
public:

    typedef typename std::vector <std::pair<RulePtr, std::vector<PureAlert> > > A;
    typedef typename A::value_type value_type;
    typedef typename A::iterator iterator;

    /*
     * \brief Creates an empty rule-alert configuration with empty path
     *
     */
    AlertConfiguration ()
        : _path{}
    {};

    /*
     * \brief Creates an empty rule-alert configuration
     *
     * \param[in] path - a directory where rules are stored
     */
    AlertConfiguration (const std::string &path)
        : _path (path)
    {};

    /*
     * \brief Reads the configuration from persistence
     *
     * Set of topics is empty if there are no rules or there are some errors
     *
     * \return a set of topics to be consumed
     */
    std::set <std::string> readConfiguration (void);

    // XXX: this exposes a lot of internal stuff - we need iterator as a class,
    // not just typedef
    iterator begin() { return _alerts.begin(); }
    iterator end() { return _alerts.end(); }
    size_t size () { return _alerts.size (); }

    /*
     * \brief Sets a path to configuration files
     *
     * \param[in] path - a directory where rules are stored
     */
    void setPath (const char* path) {
        _path = path;
    }

    /*
     * \brief Adds a rule to the configuration
     *
     * alertsToSend must be sent in the order from the first element to the last element
     *
     * \param[in] newRuleString - an input stream to parse a rule
     * \param[out] newSubjectsToSubscribe - subjects that are required by the new rule
     * \param[out] alertsToSend - alerts that where affected by new rule
     * \param[out] it - iterator to the new rule
     *
     * \return -1 when rule has error in JSON
     *         -2 when rule with such name already exists
     *         -5 when rule has error in lua
     *         -6 disk manipulation error (storing, moving...)
     *          0 when rule was parsed and added correctly (but it can be not saved)
     */
    int addRule (
        std::istream &newRuleString,
        std::set <std::string> &newSubjectsToSubscribe,
        std::vector <PureAlert> &alertsToSend,
        iterator &it);

    /*
     * \brief Updates existing rule in the configuration
     *
     * alertsToSend must be sent in the order from the first element to the last element
     *
     * \param[in] newRuleString - an input stream to parse a rule
     *              (can have a new name for this rule)
     * \param[in] rule_name - old name of the rule
     * \param[out] newSubjectsToSubscribe - subjects that are required by the new rule
     * \param[out] alertsToSend - alerts that where affected by new rule
     * \param[out] it - iterator to the new rule
     *
     * \return -2 when rule with old_name doesn't exist -> nothing to update
     *         -1 when rule has error in JSON
     *         -5 when rule has error in lua
     *         -3 if name of the rule is changed, but for the new name rule
     *            already exists
     *         -6 disk manipulation error (storing, moving...)
     *          0 when rule was parsed and updated correctly (but it can be not saved)
     */
    int updateRule (
        std::istream &newRuleString,
        const std::string &rule_name,
        std::set <std::string> &newSubjectsToSubscribe,
        std::vector <PureAlert> &alertsToSend,
        iterator &it);

    /*
     * \brief Touch existing rule in the configuration.
     * 
     * Indicats that something in rule was changed implicitly.
     *
     * alertsToSend must be sent in the order from the first element to the last element
     *
     * \param[in] rule_name - name of the rule to touch
     * \param[out] alertsToSend - alerts that where affected by this rule
     *
     * \return -1 when rule with rule_name doesn't exist -> nothing to update
     *          0 when rule was touched successfully
     */
    int touchRule (
        const std::string &rule_name,
        std::vector <PureAlert> &alertsToSend);

    /*
     * \brief Incapsulates alert in the model
     *
     * \param[in] rule - the evaluated rule
     * \param[in] pureAlert - the result of the evaluation (alert)
     * \param[out] alert_to_send - the alert prepared to send
     *
     * \return -1 nothing to send
     *          0 need to send an alert
     */
    int updateAlert (
        const RulePtr &rule,
        const PureAlert &pureAlert,
        PureAlert &alert_to_send);

    bool haveRule (const RulePtr &rule) const {
        return haveRule (rule->name ());
    };

    bool haveRule (const std::string &rule_name) const {
        for ( const auto &i: _alerts ) {
            const auto &oneKnownRule = i.first;
            if ( oneKnownRule->hasSameNameAs(rule_name) )
                return true;
        }
        return false;
    };

    int
        updateAlertState (
                const char *rule_name,
                const char *element_name,
                const char *new_state,
                PureAlert &pureAlert);

    std::string getPersistencePath(void) const {
        return _path + '/';
    }

private:

    // rules and corresponding alerts
    A _alerts;

    // directory, where rules are stored
    std::string _path;
};

#endif // SRC_ALERTCONFIGURATION_H
