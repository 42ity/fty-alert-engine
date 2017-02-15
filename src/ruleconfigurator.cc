/*  =========================================================================
    ruleconfigurator - Rule Configurator

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
    =========================================================================
*/

/*
@header
    ruleconfigurator - Rule Configurator
@discuss
@end
*/

#include "fty_alert_engine_classes.h"

#include <cstring>
#include <ostream>
#include <limits>
#include <mutex>
#include <cxxtools/jsonformatter.h>
#include <cxxtools/convert.h>
#include <cxxtools/regex.h>
#include <cxxtools/serializationinfo.h>
#include <cxxtools/split.h>

#include <string>
//#include <math.h>

#include "autoconfig.h"
#include "ruleconfigurator.h"

// General template for whether type T (a standard container) is iterable
// We deliberatelly don't want to solve this for general case (we don't need it)
// If we ever need a general is_container - http://stackoverflow.com/a/9407521
template <typename T>
struct is_iterable {
    static const bool value = false;
};    

// Partial specialization for std::vector
template <typename T,typename Alloc>
struct is_iterable<std::vector <T,Alloc> > {
    static const bool value = true;
};    

// Partial specialization for std::list
template <typename T,typename Alloc>
struct is_iterable<std::list <T,Alloc> > {
    static const bool value = true;
};

std::string escape (const char *string) {
    if (!string)
        return "(null_ptr)";

    std::string after;
    std::string::size_type length = strlen (string);
    after.reserve (length * 2);

    /*
     * Quote from http://www.json.org/
     * -------------------------------
     * Char
     *  any-Unicode-character-except-"-or-\-or-control-character:
     *  \"
     *  \\
     *  \/
     *  \b
     *  \f
     *  \n
     *  \r
     *  \t
     *  \u four-hex-digits 
     * ------------------------------
     */

    for (std::string::size_type i = 0; i < length; ++i) {
        char c = string[i];
        if (c == '"') {
            after.append ("\\\"");
        }
        else if (c =='\b') {
            after.append ("\\\\b");
        }   
        else if (c =='\f') {
            after.append ("\\\\f");
        }   
        else if (c == '\n') {
            after.append ("\\\\n");
        }
        else if (c == '\r') {
            after.append ("\\\\r");

        }
        else if (c == '\t') {
            after.append ("\\\\t");
        }
        else if (c == '\\') {
            after.append ("\\\\");
        }
        else {
            after += c;
        }
    }       
    return after;
}       

std::string escape (const std::string& before) {
    return escape (before.c_str ());
}   

std::string jsonify (double t)
{
    if (isnan(t))
        return "null";
    return std::to_string (t);
}

template <typename T
, typename = typename std::enable_if<std::is_arithmetic<T>::value>::type>
std::string jsonify (T t) {
    try {
        return escape (std::to_string (t));
    } catch (...) {
        return ""; 
    }
}   

// TODO: doxy
// basically, these are property "jsonifyrs"; you supply any json-ifiable type pair and it creates a valid, properly escaped property (key:value) pair out of it.
// single arg version escapes and quotes were necessary (i.e. except int types...)

template <typename T
, typename std::enable_if<std::is_convertible<T, std::string>::value>::type* = nullptr>
std::string jsonify (const T& t) {
    try {
        return std::string ("\"").append (escape (t)).append ("\"");
    } catch (...) {
        return ""; 
    }
}   

template <typename T
, typename std::enable_if<is_iterable<T>::value>::type* = nullptr>
std::string jsonify (const T& t) {
    try {
        std::string result = "[ ";
        bool first = true;
        for (const auto& item : t) {
            if (first) {
                result += jsonify (item);
                first = false;
            }
            else { 
                result += ", " + jsonify (item);
            }   
        }       
        result += " ]";
        return result;
    } catch (...) {
        return "[]";
    }
}       

template <typename S
, typename std::enable_if<std::is_convertible<S, std::string>::value>::type* = nullptr
, typename T
, typename std::enable_if<std::is_convertible<T, std::string>::value>::type* = nullptr>
std::string jsonify (const S& key, const T& value) {
    return std::string (jsonify (key)).append (" : ").append (jsonify (value));
}

template <typename S
, typename = typename std::enable_if<std::is_convertible<S, std::string>::value>::type
, typename T
, typename = typename std::enable_if<std::is_arithmetic<T>::value>::type>
std::string jsonify (const S& key, T value) {
    return std::string (jsonify (key)).append (" : ").append (jsonify (value));
}

template <typename S
, typename std::enable_if<std::is_convertible<S, std::string>::value>::type* = nullptr
, typename T
, typename std::enable_if<std::is_arithmetic<T>::value>::type* = nullptr>
std::string jsonify (T key, const S& value) {
    return std::string ("\"").append (jsonify (key)).append ("\" : ").append (jsonify (value));
}

template <typename T
, typename = typename std::enable_if<std::is_arithmetic<T>::value>::type>
std::string jsonify (T key, T value) {
    return std::string ("\"").append (jsonify (key)).append ("\" : ").append (jsonify (value));
}

template <typename S
, typename std::enable_if<std::is_convertible<S, std::string>::value>::type* = nullptr
, typename T
, typename std::enable_if<is_iterable<T>::value>::type* = nullptr>
std::string jsonify (const S& key, const T& value) {
    return std::string (jsonify (key)).append (" : ").append (jsonify (value));
}

template <typename S
, typename std::enable_if<is_iterable<S>::value>::type* = nullptr
, typename T
, typename std::enable_if<std::is_arithmetic<T>::value>::type* = nullptr>
std::string jsonify (T key, const S& value) {
    return std::string ("\"").append (jsonify (key)).append ("\" : ").append (jsonify (value));
}

bool RuleConfigurator::sendNewRule (const std::string& rule, mlm_client_t *client)
{
    if (!client)
        return false;
    zmsg_t *message = zmsg_new (); 
    zmsg_addstr (message, "ADD");
    zmsg_addstr (message, rule.c_str());
    if (mlm_client_sendto (client, Autoconfig::AlertEngineName.c_str (), "rfc-evaluator-rules", NULL, 5000, &message) != 0) {
        zsys_error ("mlm_client_sendto (address = '%s', subject = '%s', timeout = '5000') failed.",
                Autoconfig::AlertEngineName.c_str (), "rfc-evaluator-rules");
        return false;
    }   
    return true;
}

std::string RuleConfigurator::makeThresholdRule (
        const std::string& rule_name,
        std::vector<std::string> topic_specification,
        const std::string& element_name,
        std::tuple <std::string, std::vector <std::string>, std::string, std::string> low_critical,
        std::tuple <std::string, std::vector <std::string>, std::string, std::string> low_warning,
        std::tuple <std::string, std::vector <std::string>, std::string, std::string> high_warning,
        std::tuple <std::string, std::vector <std::string>, std::string, std::string> high_critical,
        const char *lua_function)
{
    assert (topic_specification.size () >= 1);

    // target
    std::string target;
    if (topic_specification.size () == 1) {
        target = jsonify ("target", topic_specification [0]);
    }
    else {
        target = jsonify ("target", topic_specification);
    }

    // values
    std::string values =
        "[ { " + jsonify ("low_critical", std::get<0>(low_critical)) + " },\n"
        "  { " + jsonify ("low_warning", std::get<0>(low_warning)) + " },\n"
        "  { " + jsonify ("high_warning", std::get<0>(high_warning)) + " },\n"
        "  { " + jsonify ("high_critical", std::get<0>(high_critical)) + " } ]";

    // results
    std::string results =
        "[ { \"low_critical\"  : { " + jsonify ("action", std::get<1>(low_critical)) + ", " + jsonify ("severity", std::get<2>(low_critical))
        + ", " + jsonify ("description", std::get<3>(low_critical))  + " }},\n"
        "  { \"low_warning\"   : { " + jsonify ("action", std::get<1>(low_warning)) + ", " + jsonify ("severity", std::get<2>(low_warning))
        + ", " + jsonify ("description", std::get<3>(low_warning)) + " }},\n"
        "  { \"high_warning\"  : { " + jsonify ("action", std::get<1>(high_warning)) + ", " + jsonify ("severity", std::get<2>(high_warning))
        + ", " + jsonify ("description", std::get<3>(high_warning)) + " }},\n"
        "  { \"high_critical\" : { " + jsonify ("action", std::get<1>(high_critical)) + ", " + jsonify ("severity", std::get<2>(high_critical))
        + ", " + jsonify ("description", std::get<3>(high_critical))+ " }} ]";

    // evaluation
    std::string evaluation;
    if (lua_function) {
        evaluation = ",\n" + jsonify ("evaluation", lua_function);
    }


    std::string result =
        "{\n"
        "\"threshold\" : {\n"
        + jsonify ("rule_name", rule_name) + ",\n"
        + target + ",\n"
        + jsonify ("element", element_name) + ",\n"
        "\"values\" : " + values +",\n"
        "\"results\" : " + results
        + evaluation + "}\n"
        "}";

    return result;
}

std::string RuleConfigurator::makeSingleRule (
        const std::string& rule_name,
        const std::vector<std::string>& target,
        const std::string& element_name,
        //                          value_name   value
        const std::vector <std::pair<std::string, std::string>>& values,
        //                           result_name               actions       severity     description 
        const std::vector <std::tuple<std::string, std::vector <std::string>, std::string, std::string>>& results,
        const std::string& evaluation)
{
    assert (target.size () >= 1);

    // values
    std::string result_values = "[ ";
    bool first = true;
    for (const auto& item : values) {
        if (first) {
            result_values += "{ " + jsonify (item.first, item.second) + " }";
            first = false;
        }
        else {
            result_values += ", { " + jsonify (item.first, item.second) + " }";
        }
    }
    result_values += " ]";

    // results
    std::string result_results = "[ ";
    first = true; 
    for (const auto& item : results) {
        if (first) {
            result_results += makeSingleRule_results (item);
            first = false;
        }
        else {
            result_results += ", " + makeSingleRule_results (item);
        }   
    }   
    result_results += " ]";


    std::string result =
        "{\n"
        "\"single\" : {\n"
        + jsonify ("rule_name", rule_name) + ",\n"
        + jsonify ("target", target) + ",\n"
        + jsonify ("element", element_name) + ",\n"
        "\"values\" : " + result_values + ",\n"
        "\"results\" : " + result_results + ",\n"
        + jsonify ("evaluation", evaluation) + "}\n"
        "}";

    return result;   

}

std::string RuleConfigurator::makeSingleRule_results (std::tuple<std::string, std::vector <std::string>, std::string, std::string> one_result)
{
    std::string result = "{ " + jsonify (std::get<0> (one_result)) + " : { ";
    result += jsonify ("action", std::get<1> (one_result)) + ", ";
    result += jsonify ("severity", std::get<2> (one_result)) + ", ";
    result += jsonify ("description", std::get<3> (one_result)) + " }}";
    return result;
}   

