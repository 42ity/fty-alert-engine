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

/*! \file rule.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief General representation of rule
 */

#ifndef SRC_RULE_H
#define SRC_RULE_H

#include <cxxtools/jsonserializer.h>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <fstream>
#include <iostream>

#include "purealert.h"

/*
 * \brief Helper structure to store a possible outcome of rule evaluation
 *
 * Rule evaluation outcome has three values:
 * - actions
 * - severity
 * - description
 */
struct Outcome {
    std::vector <std::string> _actions;
    std::string _severity;
    std::string _description;
};

/*
 * \brief Serialzation of outcome
 */
void operator<<= (cxxtools::SerializationInfo& si, const Outcome& outcome)
{
    si.addMember("actions") <<= outcome._actions;
    si.addMember("severity") <<= outcome._severity;
    si.addMember("description") <<= outcome._description;
};

/*
 * \brief Deserialzation of outcome
 */
void operator>>= (const cxxtools::SerializationInfo& si, Outcome& outcome)
{
    si.getMember("actions") >>= outcome._actions;
    si.getMember("severity") >>= outcome._severity;
    si.getMember("description") >>= outcome._description;
};

/*
 * \brief General representation for rules
 */
class Rule {

public:

    /* Every rule should have a rule name */
    std::string _rule_name;

    // user is able to define his own constants, that should be used in evaluation
    std::map <std::string, double> _values;

    // user is able to define his own set of results, that should be used in evaluation
    std::map <std::string, Outcome> _outcomes;


    /* TODO rework this part, as it it legacy already*/
    /* Every rule produces alerts for element */ // TODO check this assumption
    std::string _element;

    /* lua_code evaluation function */ // TODO move to derived clases 
    std::string _lua_code;
    /* Every rule has its severity */ // TODO remove it
    std::string _severity;
    // this field doesn't have any impact on alert evaluation
    // but this information should be propagated to GATEWAY components
    // So, need to have it here
    // TODO: remove  it. it is legacy already
    std::set <std::string> _actions;

    /*
     * \brief Evaluates the rule
     *
     * \param[in] metricList - a list of known metrics
     * \param[out] pureAlert - result of evaluation
     *
     * \return 0 if evaluation was correct
     *         non 0 if there were some errors during the evaluation
     */
    virtual int evaluate (const MetricList &metricList, PureAlert **pureAlert) const = 0;

    /*
     * \brief Checks if topic is necessary for rule evaluation
     *
     * \param[in] topic - topic to check
     *
     * \return true/false
     */
    virtual bool isTopicInteresting(const std::string &topic) const = 0;

    /*
     * \brief Returns a set of topics, that are necessary for rule evaluation
     *
     * \return a set of topics
     */
    virtual std::set<std::string> getNeededTopics(void) const = 0;

    /*
     * \brief Checks if rules have same names
     *
     * \param[in] rule - rule to check
     *
     * \return true/false
     */
    bool hasSameNameAs (const Rule &rule) const {
        return hasSameNameAs (rule._rule_name);
    };

    /*
     * \brief Checks if rules have same names
     *
     * \param[in] rule - pointer to the rule to check
     *
     * \return true/false
     */
    bool hasSameNameAs (const Rule *rule) const {
        return hasSameNameAs (rule->_rule_name);
    };

    /*
     * \brief Checks if rule has this name
     *
     * \param[in] name - name to check
     *
     * \return true/false
     */
    bool hasSameNameAs (const std::string &name) const {
        if ( this->_rule_name == name ) {
            return true;
        }
        else {
            return false;
        }
    };

    /*
     * \brief Gets a json representation of the rule
     *
     * \return json representation of the rule as string
     */
    std::string getJsonRule (void) const {
        return _json_representation;
    };

    /*
     * \brief Save rule to the persistance
     */
    void save (void) {
        // ASSUMPTION: file name is the same as rule name
        // rule name and file name are CASE SENSITIVE.

        std::string path = _rule_name + ".rule";
        std::ofstream ofs (path, std::ofstream::out);
        //zsys_info ("here must be json: '%s'", _json_representation.c_str());
        //zsys_info ("here must be file name: '%s'", path.c_str());
        ofs << _json_representation;
        ofs.close();
        return;
    };

    std::string getType(void) {
        return _type_name;
    };

    virtual ~Rule () {};

    friend Rule* readRule (std::istream &f);

protected:

    // every type of the rule should have a string representation of its name
    std::string _type_name;

    std::string _json_representation;

    /*
     * \brief User cannot construct object of abstract entity
     */
    Rule(){};
};

#endif // SRC_RULE_H
