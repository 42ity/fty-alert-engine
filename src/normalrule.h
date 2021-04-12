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

/*! \file normalrule.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Representation of normal rule
 */
#ifndef SRC_NORMALRULE_H
#define SRC_NORMALRULE_H

#include <cxxtools/serializationinfo.h>
#include "luarule.h"
extern "C" {
#include <lua5.1/lua.h>
#include <lua5.1/lauxlib.h>
}
// because of zsys
#include <czmq.h>
#include <fty_log.h>
class NormalRule : public LuaRule
{
public:
    NormalRule(){};

    std::string whoami () const { return "single"; }

    /*
     * \brief parse json and check lua and fill the object
     *
     * ATTENTION: throws, if bad JSON
     *
     * \return 1 if rule has other type
     *         2 if lua function has errors
     *         0 if everything is ok
     */
    int fill(const cxxtools::SerializationInfo &si)
    {
        _si = si;
        if ( si.findMember("single") == NULL ) {
            return 1;
        }
        log_debug ("it is SINGLE rule");
        auto single = si.getMember("single");
        if ( single.category () != cxxtools::SerializationInfo::Object ) {
            log_error ("Root of json must be an object with property 'single'.");
            throw std::runtime_error("Root of json must be an object with property 'single'.");
        }

        // target
        auto target = single.getMember("target");
        if ( target.category () != cxxtools::SerializationInfo::Array ) {
            log_error ("property 'target' in json must be an Array");
            throw std::runtime_error ("property 'target' in json must be an Array");
        }
        target >>= _metrics;
        single.getMember("rule_name") >>= _name;
        single.getMember("element") >>= _element;
        // rule_class
        if ( single.findMember("rule_class") != NULL ) {
            single.getMember("rule_class") >>= _rule_class;
        }
        // rule_source
        if ( single.findMember("rule_source") == NULL ) {
            // if key is not there, take default
            _rule_source = "Manual user input";
            single.addMember("rule_source") <<= _rule_source;
        }
        else {
            auto rule_source = single.getMember("rule_source");
            if ( rule_source.category () != cxxtools::SerializationInfo::Value ) {
                throw std::runtime_error("'rule_source' in json must be value.");
            }
            rule_source >>= _rule_source;
        }
        log_debug ("rule_source = %s", _rule_source.c_str());
        // values
        // values are not required for single rule
        if ( single.findMember("values") != NULL ) {
            std::map<std::string,double> tmp_values;
            auto values = single.getMember("values");
            if ( values.category () != cxxtools::SerializationInfo::Array ) {
                log_error ("parameter 'values' in json must be an array.");
                throw std::runtime_error("parameter 'values' in json must be an array");
            }
            values >>= tmp_values;
            globalVariables(tmp_values);
        }

        // outcomes
        auto outcomes = single.getMember("results");
        if ( outcomes.category () != cxxtools::SerializationInfo::Array ) {
            log_error ("parameter 'results' in json must be an array.");
            throw std::runtime_error ("parameter 'results' in json must be an array.");
        }
        outcomes >>= _outcomes;

        std::string tmp;
        single.getMember("evaluation") >>= tmp;
        try {
            code(tmp);
        }
        catch ( const std::exception &e ) {
            log_warning ("something with lua function: %s", e.what());
            return 2;
        }
        return 0;
    }
};

#endif // SRC_NORMALRULE_H_
