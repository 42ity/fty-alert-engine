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

#include "regexrule.h"
#include "misc/json.h"

#include <fty_log.h>

int RegexRule::fill(const cxxtools::SerializationInfo& si)
{
    _si = si;

    // *must* pattern root object
    const std::string rootName{"pattern"};
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
    _rex_str = JSON::getString(target);

    // build zrex object
    _rex = zrex_new(_rex_str.c_str()); // TODO: what if regexp is not correct?
    if (!_rex) {
        log_error("zrex_new() failed (rex: %s)", _rex_str.c_str());
        return 1; // not recognized
    }

    log_debug("Rule class: %s, root: %s)", clazz().c_str(), rootName.c_str());

    _name = JSON::getStringUtf8(JSON::findMember(root, "rule_name"));
    _rule_class = JSON::getString(JSON::findMember(root, "rule_class"));
    // no _element (rex runtime)

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

/// returns 0 if ok (pureAlert initialized)
int RegexRule::evaluate(const MetricList& metricList, PureAlert& pureAlert)
{
    _metrics = {metricList.getLastMetric().getTopic()};

    int r = LuaRule::evaluate(metricList, pureAlert);
    if (r == 0) { // ok
        // regexp rule is special, it has to generate alert for the asset
        // that trigger the evaluation
        pureAlert._element = metricList.getLastMetric().getAssetName();
    }
    return r;
}

bool RegexRule::isTopicInteresting(const std::string& topic) const
{
    return _rex ? zrex_matches(_rex, topic.c_str()) : false;
}

std::vector<std::string> RegexRule::getNeededTopics() const
{
    return std::vector<std::string>{_rex_str};
}
