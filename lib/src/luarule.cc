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

#include "luarule.h"
#include "audit_log.h"
#include <algorithm>
#include <fty_log.h>

LuaRule::~LuaRule()
{
    if (_lstate)
        { lua_close(_lstate); _lstate = NULL; }
}

LuaRule::LuaRule(const LuaRule& r)
{
    _name = r._name;
    globalVariables(r.getGlobalVariables());
    code(r._code);
}

void LuaRule::globalVariables(const std::map<std::string, double>& vars)
{
    Rule::globalVariables(vars);
    luaSetGlobalVariables();
}

void LuaRule::code(const std::string& newCode)
{
    _valid = false;

    // cleanup
    _code.clear();
    if (_lstate)
        { lua_close(_lstate); _lstate = NULL; }

    // create new Lua state
#if LUA_VERSION_NUM > 501
    _lstate = luaL_newstate();
#else
    _lstate = lua_open();
#endif
    if (!_lstate) {
        throw std::runtime_error("Can't initiate Lua context!");
    }

    // load common functions like print()
    luaL_openlibs(_lstate);

    // set _code *first* then set Lua globals
    _code = newCode;
    luaSetGlobalVariables();

    // compile Lua code
    int r = luaL_dostring(_lstate, _code.c_str());
    if (r != LUA_OK) {
        const char* luaError = lua_tostring(_lstate, -1);
        log_error("Lua error: %s", luaError);
        lua_pop(_lstate, 1);
        throw std::runtime_error("Lua code compilation failed!");
    }

    // check there is a main() function
    lua_getglobal(_lstate, "main");
    r = lua_isfunction(_lstate, lua_gettop(_lstate));
    if (r != 1) {
        lua_pop(_lstate, 1);
        throw std::runtime_error("Lua main function not found!"); // missing
    }
    lua_pop(_lstate, 1);

    _valid = true; // ok
}

static std::string auditValue(const std::string& metric, double value)
{
    char svalue[32] = "";
    if (!std::isnan(value)) {
        snprintf(svalue, sizeof(svalue), "%0.2lf", value);
        char* p = strstr(svalue, ".00");
        if (p) { *p = 0; } // remove .00 decimals
    }
    // <metricName>=<value> format
    return metric.substr(0, metric.find("@")) + "=" + std::string{svalue};
}

int LuaRule::evaluate(const MetricList& metricList, PureAlert& pureAlert)
{
    log_debug("LuaRule::evaluate %s", _name.c_str());
    int res = 0;

    std::string auditValues;

    std::vector<double> values;
    int index = 0;
    for (const auto& metric : _metrics) {
        double value = metricList.find(metric);

        auditValues += (auditValues.empty() ? "" : ", ") + auditValue(metric, value);

        if (std::isnan(value)) {
            log_debug("metric#%d: %s = NaN", index, metric.c_str());
            log_debug("Don't have everything for '%s' yet", _name.c_str());
            res = RULE_RESULT_UNKNOWN; // assume != 0
            break;
        }
        values.push_back(value);
        log_debug("metric#%d: %s = %lf", index, metric.c_str(), value);
        index++;
    }

    if (res != RULE_RESULT_UNKNOWN) {
        int status = static_cast<int>(luaEvaluate(values));
        auto now = static_cast<uint64_t>(::time(NULL));

        if (status == RULE_RESULT_OK) {
            log_debug("LuaRule::evaluate %s %s", _name.c_str(), "RESOLVED");
            // When alert is resolved, it doesn't have new severity
            const std::string description{"The alarm is now resolved"};
            const std::string severity{"OK"};
            pureAlert = PureAlert(ALERT_RESOLVED, now, description, _element, severity, {""});
            //pureAlert.print();
        }
        else {
            const std::string statusText = resultToString(status);

            auto outcome = _outcomes.find(statusText);
            if (outcome == _outcomes.cend()) {
                // BSOS-1570, some alerts are malformed, missing result definition gives no outcome
                // WA: choose a similar outcome from status (if any)
                const std::vector<std::pair<std::string, std::string>> similarStatus = {
                    std::pair("low_critical", "low_warning"),   // see text_results[]
                    std::pair("high_warning", "high_critical"),
                };
                for (const auto& it : similarStatus) {
                    if (statusText == it.first ) { outcome = _outcomes.find(it.second); break; }
                    if (statusText == it.second) { outcome = _outcomes.find(it.first ); break; }
                }

                if (outcome != _outcomes.cend()) {
                    log_warning("LuaRule::evaluate %s '%s' result not defined, fallback to '%s'",
                        _name.c_str(), statusText, outcome->first.c_str());
                }
            }

            if (outcome != _outcomes.cend()) {
                // Some known outcome was found
                log_debug("LuaRule::evaluate %s START %s", _name.c_str(), outcome->second._severity.c_str());
                pureAlert = PureAlert(ALERT_START, now, outcome->second._description, _element, outcome->second._severity, outcome->second._actions);
                pureAlert.print();
            }
            else {
                log_error("LuaRule::evaluate %s '%s' result returned, but not defined",
                    _name.c_str(), statusText);
                res = RULE_RESULT_UNKNOWN;
            }
        }
    }

    // log audit alarm
    std::string auditDesc =
        (res == RULE_RESULT_UNKNOWN) ? ALERT_UNKNOWN : // UNKNOWN
        (pureAlert._status == ALERT_RESOLVED) ? ALERT_RESOLVED : // RESOLVED
        std::string{pureAlert._status + "/" + pureAlert._severity.substr(0, 1)} // ACTIVE/C ACTIVE/W
    ;
    std::string alertName{_name};
    if (alertName == "warranty") {
        // "warranty" alert exception (no specified asset)
        // extract asset name from "end_warranty_date" metric (first)
        if (_metrics.size() > 0) {
            std::string metric{_metrics[0]};
            std::string iname{metric.substr(metric.find("@"))};
            alertName += iname; // completed w/ device @iname
        }
    }
    audit_log_info("%8s %s (%s)", auditDesc.c_str(), alertName.c_str(), auditValues.c_str());

    return res;
}

double LuaRule::luaEvaluate(const std::vector<double>& arguments)
{
    if (!_valid) {
        throw std::runtime_error("Lua rule is not valid!");
    }
    if (!_lstate) { // secure
        throw std::runtime_error("Lua state is NULL!");
    }

    lua_settop(_lstate, 0);

    lua_getglobal(_lstate, "main");
    for (const auto arg : arguments) {
        lua_pushnumber(_lstate, arg);
    }

    int r = lua_pcall(_lstate, static_cast<int>(arguments.size()), 1, 0);
    if (r != 0) {
        const char* luaError = lua_tostring(_lstate, -1);
        log_error("Lua error: %s", luaError);
        lua_pop(_lstate, 1);
        throw std::runtime_error("Lua calling main failed!");
    }

    if (!lua_isnumber(_lstate, -1)) {
        throw std::runtime_error("Lua function main did not return a number!");
    }

    double ret = lua_tonumber(_lstate, -1);
    lua_pop(_lstate, 1);
    return ret;
}

void LuaRule::luaSetGlobalVariables()
{
    if (!_lstate) {
        return; // no state to set
    }

    // register results name/value in state
    for (int result = RULE_RESULT_TO_LOW_CRITICAL; result <= RULE_RESULT_UNKNOWN; result++) {
        std::string resultName = Rule::resultToString(result);
        transform(resultName.begin(), resultName.end(), resultName.begin(), ::toupper); // UPPER
        lua_pushnumber(_lstate, result); // value
        lua_setglobal(_lstate, resultName.c_str()); // variable name
    }

    std::map<std::string, double> globals{getGlobalVariables()};

    if (!globals.empty()) {
        // BSOS-1570, some alerts are malformed, missing values definition (thresholds)
        // where evaluation gives the error "Lua calling main() failed!"
        // WA: ensure referenced globals are defined with compliant threshold values
        // with ascending order from low_critical to high_critical (code logic)

        // NOTICE: _code *must* be set (non empty) to be efficient (see LuaRule::code())
        // eg. if _code is empty, the variable will always be added
        uint added{0};
        std::string addedVars;

        auto setGlobalIfUsed = [this, &globals, &added, &addedVars] (const std::string& name, double value) {
            if (_code.empty() // considered as used if code is empty
                || (_code.find(name) != std::string::npos) // variable used in code
            ) {
                globals[name] = value;
                addedVars += (addedVars.empty() ? "" : ", ") + name + "=" + std::to_string(value);
                added++;
            }
        };

        const std::string LC{"low_critical"}; // see text_results[]
        const std::string LW{"low_warning"};
        const std::string HW{"high_warning"};
        const std::string HC{"high_critical"};

        const bool hasLC{globals.count(LC) != 0};
        const bool hasLW{globals.count(LW) != 0};
        const bool hasHW{globals.count(HW) != 0};
        const bool hasHC{globals.count(HC) != 0};

        const double BIG{1.0E+8}; // huge threshold, >0
        const double EPS{1.0E-3}; // epsilon, >0

        // auto completion of required LOW globals
        if (hasLC && !hasLW) {
            setGlobalIfUsed(LW, globals[LC] + EPS);
        }
        else if (!hasLC && hasLW) {
            setGlobalIfUsed(LC, globals[LW] - BIG);
        }
        else if (!hasLC && !hasLW) {
            setGlobalIfUsed(LC, -BIG);
            setGlobalIfUsed(LW, -BIG + EPS);
        }

        // auto completion of required HIGH globals
        if (hasHW && !hasHC) {
            setGlobalIfUsed(HC, globals[HW] + BIG);
        }
        else if (!hasHW && hasHC) {
            setGlobalIfUsed(HW, globals[HC] - EPS);
        }
        else if (!hasHW && !hasHC) {
            setGlobalIfUsed(HW, BIG - EPS);
            setGlobalIfUsed(HC, BIG);
        }

        if (added != 0) {
            logDebug("{} has {} missing globals (auto completion: {})", _name, added, addedVars);
        }
    }

    // register globals name/value in state
    for (const auto& it : globals) {
        lua_pushnumber(_lstate, it.second); // value
        lua_setglobal(_lstate, it.first.c_str()); // variable name
    }
}
