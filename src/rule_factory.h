/*  =========================================================================
    asset_factory - Rule factory

    Copyright (C) 2019 - 2019 Eaton

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

#ifndef RULE_FACTORY_H_INCLUDED
#define RULE_FACTORY_H_INCLUDED

#include <stdexcept>
#include <memory>
#include <cxxtools/serializationinfo.h>
#include <cxxtools/jsondeserializer.h>
#include <sstream>
#include <fty_log.h>

// force proper header order
#include "rule.h"
#include "extended_rules.h"

#include "fty_alert_engine_classes.h"

class RuleFactory {
    private:
        template <typename T>
        static std::unique_ptr<Rule> createRuleByName (const std::string &name, const T ruleSource) {
            if (name == "single") {
                return std::unique_ptr<Rule>(new SingleRule (ruleSource));
            } else if (name == "pattern") {
                return std::unique_ptr<Rule>(new PatternRule (ruleSource));
            } else if (name == "threshold") {
                return std::unique_ptr<Rule>(new ThresholdRule (ruleSource));
            } else if (name == "flexible") {
                return std::unique_ptr<Rule>(new FlexibleRule (ruleSource));
            } else {
                throw std::runtime_error ("Unrecognized rule");
            }
        }
    public:
        /// create Rule object from cxxtools::SerializationInfo
        static std::unique_ptr<Rule> createFromSerializationInfo (const cxxtools::SerializationInfo &si) {
            const cxxtools::SerializationInfo &elem_content = si.getMember (0);
            if (elem_content.category () != cxxtools::SerializationInfo::Object) {
                log_error ("Root of json must be type object.");
                throw std::runtime_error ("Root of json must be type object.");
            }
            try {
                return createRuleByName (elem_content.name (), si);
            } catch (std::exception &e) {
                std::ostringstream oss;
                si.dump (oss);
                log_error ("Unrecognized rule '%s'", oss.str ().c_str ());
                throw std::runtime_error ("Unrecognized rule");
            }
        }
        /// create Rule object from JSON format
        static std::unique_ptr<Rule> createFromJson (const std::string &json) {
            std::istringstream iss (json);
            cxxtools::JsonDeserializer jd (iss);
            try {
                cxxtools::SerializationInfo si;
                jd.deserialize (si);
                return createFromSerializationInfo (si);
                //createRuleByName (elem_content.name (), json);
            } catch (std::exception &e) {
                throw std::runtime_error ("JSON deserializer has null SerializationInfo for input: " + json);
            }
        }
};

#endif
