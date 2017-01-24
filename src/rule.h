/*
 * Copyright (C) 2014 - 2017 Eaton
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*! \file rule.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief General representation of rule
 */

#ifndef SRC_RULE_H
#define SRC_RULE_H
#include <cxxtools/jsondeserializer.h>
#include <cxxtools/jsonserializer.h>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <fstream>
#include <iostream>
#include <czmq.h>

#include "purealert.h"
#include "metriclist.h"

#ifndef zsys_debug1
extern int agent_alert_verbose;
#define zsys_debug1(...) \
    do { if (agent_alert_verbose) zsys_debug (__VA_ARGS__); } while (0);
#endif

//  1  - equals
//  0  - different
// -1  - error
int
utf8eq (const std::string& s1, const std::string& s2);

void
si_getValueUtf8 (const cxxtools::SerializationInfo& si, const std::string& member_name, std::string& result);

/*
 * \brief Helper structure to store a possible outcome of rule evaluation
 *
 * Rule evaluation outcome has three values:
 * - actions
 * - severity // severity is detected automatically !!!! user cannot change it
 * - description
 */
struct Outcome {
    std::vector <std::string> _actions;
    std::string _severity;
    std::string _description;
};

static const char *text_results[] = {"high_critical", "high_warning", "ok", "low_warning", "low_critical", "unknown" };

/*
 * \brief Serialzation of outcome
 */
void operator<<= (cxxtools::SerializationInfo& si, const Outcome& outcome);

/*
 * \brief Deserialzation of outcome
 */
void operator>>= (const cxxtools::SerializationInfo& si, Outcome& outcome);


void operator>>= (const cxxtools::SerializationInfo& si, std::map <std::string, double> &values);


void operator>>= (const cxxtools::SerializationInfo& si, std::map <std::string, Outcome> &outcomes);

enum RULE_RESULT {
    RULE_RESULT_TO_LOW_CRITICAL  = -2,
    RULE_RESULT_TO_LOW_WARNING   = -1,
    RULE_RESULT_OK               =  0,
    RULE_RESULT_TO_HIGH_WARNING  =  1,
    RULE_RESULT_TO_HIGH_CRITICAL =  2,
    RULE_RESULT_UNKNOWN          =  3,
};

class Rule;
typedef std::unique_ptr<Rule> RulePtr;

/*
 * \brief General representation for rules
 */
class Rule {

public:
    virtual std::string whoami () const { return ""; };
    std::string name (void) const { return _name; }

    void name (const std::string &name) { _name = name; }

    std::string rule_class (void) const { return _rule_class; }
    void rule_class (const std::string &rule_class) { _rule_class = rule_class; }

    virtual int fill(const cxxtools::SerializationInfo &si) = 0;

    virtual void globalVariables (const std::map<std::string,double> &vars) {
        _variables.clear ();
        _variables.insert (vars.cbegin (), vars.cend ());
    }

   virtual std::map<std::string,double> getGlobalVariables (void) const {
        return _variables;
    }

    /**
     * \brief get/set code
     */
    virtual void code(const std::string &code) {
        throw std::runtime_error("Method not supported by this type of rule");
    };

    virtual std::string code(void) const{
        throw std::runtime_error("Method not supported by this type of rule");
    };

    /*
     * \brief User is able to define his own set of result,
     *          that should be used in evaluation
     *
     * Maps result name into the definition of possible outcome.
     * Outcome name "ok" (case sensitive) for outcome is reserved
     * and cannot be redefined by user.
     *
     * TODO make it private
     */
    std::map <std::string, Outcome> _outcomes;


    /* TODO rework this part, as it it legacy already*/
    /* Every rule produces alerts for element */ // TODO check this assumption
    std::string _element;

    /*
     * \brief Evaluates the rule
     *
     * \param[in] metricList - a list of known metrics
     * \param[out] pureAlert - result of evaluation
     *
     * \return 0 if evaluation was correct
     *         non 0 if there were some errors during the evaluation
     */
    virtual int evaluate (const MetricList &metricList, PureAlert &pureAlert) = 0;

    /*
     * \brief Checks if topic is necessary for rule evaluation
     *
     * \param[in] topic - topic to check
     *
     * \return true/false
     */
    virtual bool isTopicInteresting(const std::string &topic) const;

    /*
     * \brief Returns a set of topics, that are necessary for rule evaluation
     *
     * \return a set of topics
     */
    virtual std::vector<std::string> getNeededTopics(void) const;

    /*
     * \brief Checks if rules have same names
     *
     * \param[in] rule - rule to check
     *
     * \return true/false
     */
    bool hasSameNameAs (const RulePtr &rule) const {
        return hasSameNameAs (rule->_name);
    };

    /*
     * \brief Checks if rule has this name
     *
     * \param[in] name - name to check
     *
     * \return true/false
     */
    bool hasSameNameAs (const std::string &name) const {
        return utf8eq (_name, name);
    };

    /*
     * \brief Gets a json representation of the rule
     *
     * \return json representation of the rule as string
     */
    std::string getJsonRule (void) const {
        std::stringstream s;
        cxxtools::JsonSerializer js (s);
        js.beautify (true);
        js.serialize (_si).finish();
        return s.str();
    };

    /*
     * \brief Save rule to the persistance
     */
    void save (const std::string &path, const std::string& name) const {
        // ASSUMPTION: file name is the same as rule name
        // rule name and file name are CASE INSENSITIVE.

        std::string full_name = path + name;
        zsys_debug1 ("trying to save file : '%s'", full_name.c_str());
        std::ofstream ofs (full_name, std::ofstream::out);
        ofs.exceptions (~std::ofstream::goodbit);
        ofs << getJsonRule ();
        ofs.close();
    };

    /*
     * \brief Delete rule from the persistance
     *
     * \param[in] path - a path to files
     *
     * \return 0 on success
     *         non-zero on error
     */
    int remove (const std::string &path) {

        std::string full_name = path + _name + ".rule";
        zsys_debug1 ("trying to remove file : '%s'", full_name.c_str());
        return std::remove (full_name.c_str());
    };

    static const char * resultToString(int result) {
        if(result > RULE_RESULT_TO_HIGH_CRITICAL || result < RULE_RESULT_TO_LOW_CRITICAL) {
            return text_results[ RULE_RESULT_UNKNOWN - RULE_RESULT_TO_LOW_CRITICAL ];
        }
        return text_results [result - RULE_RESULT_TO_LOW_CRITICAL];
    }

    static int resultToInt(const char *result) {
        if( result == NULL ) return RULE_RESULT_UNKNOWN;
        for(int i = RULE_RESULT_TO_LOW_CRITICAL; i <= RULE_RESULT_TO_HIGH_CRITICAL; i++) {
            if( strcmp( text_results[ i - RULE_RESULT_TO_LOW_CRITICAL ], result ) == 0 ) {
                return i;
            }
        }
        return RULE_RESULT_UNKNOWN;
    }

    virtual ~Rule () {};

protected:
    /*
     * \brief Vector of metrics to be evaluated
     */
    std::vector<std::string> _metrics;

    /*
     * \brief Every rule should have a rule name
     *
     * ASSUMPTION: rule name has only ascii characters.
     * TODO This assumtion is not check anywhere.
     *
     * Rule name treated as case INSENSITIVE string
     */
    std::string _name;

    cxxtools::SerializationInfo _si;


    std::string _rule_source;

    /*
     * \brief Human readable info about this rule purpose like "internal temperature"
     */
    std::string _rule_class;
private:
    /*
     * \brief User is able to define his own constants,
     *          that can be used in evaluation function
     *
     * Maps name of the variable to the value.
     */
    std::map <std::string, double> _variables;


};

#endif // SRC_RULE_H
