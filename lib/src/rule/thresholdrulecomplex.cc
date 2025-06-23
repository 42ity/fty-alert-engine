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

/*!
 *  \file thresholdrulecomplex.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Complex threshold rule representation
 */

#include "thresholdrulecomplex.h"
#include "misc/json.h"

#include <fty_log.h>

int ThresholdRuleComplex::fill(const cxxtools::SerializationInfo& si)
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

    // *must* target defined as array
    auto target{JSON::findMember(root, "target")};
    if (!JSON::isArray(target)) {
        return 1; // not recognized
    }
    *target >>= _metrics;

    log_debug("Rule class: %s, root: %s)", clazz().c_str(), rootName.c_str());

    _name = JSON::getStringUtf8(JSON::findMember(root, "rule_name"));
    _element = JSON::getStringUtf8(JSON::findMember(root, "element"));
    _rule_class = JSON::getString(JSON::findMember(root, "rule_class"));

    // rule_source (not used, useless!?)
    std::string _rule_source = JSON::getString(JSON::findMember(root, "rule_source"));
    if (_rule_source.empty()) {
        // Undefined: update _si w/ default (required!?)
        _rule_source = RULE_SOURCE_DEFAULT;
        JSON::setObjectProperty(_si.findMember(rootName), "rule_source", _rule_source);
    }

    // outcomes
    _outcomes = JSON::getMapOutcome(JSON::findMember(root, "results"));

    // values (TODO: check low_critical<low_warning<high_warning<high_critical)
    globalVariables(JSON::getMapDouble(JSON::findMember(root, "values")));

    // evaluation (Lua code)
    try {
        const std::string evaluation{JSON::getString(JSON::findMember(root, "evaluation"))};
        code(evaluation);
    }
    catch (const std::exception& e) {
        log_error("Invalid Lua code (e: %s)", e.what());
        return 2; // error
    }

    return 0; // recognized and initialized correctly
}
