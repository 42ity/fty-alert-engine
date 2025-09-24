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

#include <catch2/catch.hpp>

#include "src/rule/rule.h"
#include "src/rule/luarule.h"
#include "src/templateruleconfigurator.h"
#include "src/alertconfiguration.h"
#include "src/misc/utils.h"

#include <fty_log.h>

static bool double_equals(double d1, double d2)
{
    return std::abs(d1 - d2) < std::numeric_limits<double>::epsilon() * (std::abs(d1 + d2) + 1);
}

static std::string readFile(const std::string& path)
{
    const std::string buf{utils::readFile(path)};
    logDebug("path {}\n{}", path, buf);
    return buf;
}

TEST_CASE("alertconfiguration readRule")
{
    setenv("BIOS_LOG_PATTERN", "%D %c [%t] -%-5p- %M (%l) %m%n", 1);
    ManageFtyLog::setInstanceFtylog("fty-alert-configuration");

    std::unique_ptr<Rule> rule;

    {
        std::string json;

        json = "{}";
        REQUIRE(readRule(json, rule) == 1); // no member

        json = "{ \"member0\":{}, \"member1\":{} }";
        REQUIRE(readRule(json, rule) == 1); // multi members

        json = "{ \"member\":{";
        REQUIRE(readRule(json, rule) == 1); // invalid

        json = "{ \"hello\":{} }";
        REQUIRE(readRule(json, rule) == 1); // unrecognized
    }

    const std::string low_critical(outcome::resultToString(outcome::RULE_RESULT_LOW_CRITICAL));
    const std::string low_warning(outcome::resultToString(outcome::RULE_RESULT_LOW_WARNING));
    const std::string high_warning(outcome::resultToString(outcome::RULE_RESULT_HIGH_WARNING));
    const std::string high_critical(outcome::resultToString(outcome::RULE_RESULT_HIGH_CRITICAL));
    logDebug("low_critical: '{}'", low_critical);
    logDebug("low_warning: '{}'", low_warning);
    logDebug("high_warning: '{}'", high_warning);
    logDebug("high_critical: '{}'", high_critical);

    const std::vector<std::string> action_EMAIL     = {"EMAIL"};
    const std::vector<std::string> action_EMAIL_SMS = {"EMAIL", "SMS"};
    const std::vector<std::string> action_EMAIL_GPO = {"EMAIL", "GPO_INTERACTION:gpo-42:open"};

    const std::string dir("test/testrules/");
    logDebug("dir: {}", dir);

    {
        std::string json(readFile(dir + "pattern.rule"));
        REQUIRE(readRule(json, rule) == 0);

        CHECK(rule->whoami() == "pattern");
        CHECK(rule->name() == "warranty2");
        CHECK(rule->rule_class() == "");
        CHECK(rule->element() == "");
        CHECK(rule->getNeededTopics() == std::vector<std::string>{"^end_warranty_date@.+"});

        std::map<std::string, double> vars = rule->globalVariables();
        CHECK(vars.size() == 2);
        CHECK(double_equals(vars[low_critical], 10.0));
        CHECK(double_equals(vars[low_warning], 60.0));
        CHECK(double_equals(vars[high_warning], 0.0));
        CHECK(double_equals(vars[high_critical], 0.0));

        Outcome oc;
        oc = rule->outcome(low_warning);
        CHECK(oc._description == "Warranty for device will expire in less than 60 days");
        CHECK(oc._severity == "WARNING");
        CHECK(oc._actions == action_EMAIL);
        oc = rule->outcome(low_critical);
        CHECK(oc._description == "Warranty for device will expire in less than 10 days");
        CHECK(oc._severity == "CRITICAL");
        CHECK(oc._actions == action_EMAIL);

        auto luaRule = std::unique_ptr<LuaRule>(dynamic_cast<LuaRule*>(rule.release()));
        REQUIRE(luaRule);
        CHECK(luaRule->code() ==
               "function main(value) if( value <= low_critical ) then return LOW_CRITICAL end if ( value <= "
               "low_warning ) then return LOW_WARNING end return OK end");
    }

    {
        std::string json(readFile(dir + "simplethreshold.rule"));
        REQUIRE(readRule(json, rule) == 0);

        CHECK(rule->whoami() == "threshold");
        CHECK(rule->name() == "simplethreshold");
        CHECK(rule->rule_class() == "example class");
        CHECK(rule->element() == "fff");
        CHECK(rule->getNeededTopics() == std::vector<std::string>{"abc@fff"});

        std::map<std::string, double> vars = rule->globalVariables();
        CHECK(vars.size() == 4);
        CHECK(double_equals(vars[low_critical], 30.0));
        CHECK(double_equals(vars[low_warning], 40.0));
        CHECK(double_equals(vars[high_warning], 50.0));
        CHECK(double_equals(vars[high_critical], 60.0));

        Outcome oc;
        oc = rule->outcome(low_warning);
        CHECK(oc._description == "wow LOW warning description");
        CHECK(oc._severity == "WARNING");
        CHECK(oc._actions == action_EMAIL);
        oc = rule->outcome(low_critical);
        CHECK(oc._description == "WOW low critical description");
        CHECK(oc._severity == "CRITICAL");
        CHECK(oc._actions == action_EMAIL_SMS);
        oc = rule->outcome(high_warning);
        CHECK(oc._description == "wow high WARNING description");
        CHECK(oc._severity == "WARNING");
        CHECK(oc._actions == action_EMAIL);
        oc = rule->outcome(high_critical);
        CHECK(oc._description == "wow high critical DESCTIPRION");
        CHECK(oc._severity == "CRITICAL");
        CHECK(oc._actions == action_EMAIL);
    }

    {
        std::string json(readFile(dir + "devicethreshold.rule"));
        REQUIRE(readRule(json, rule) == 0);

        CHECK(rule->whoami() == "threshold");
        CHECK(rule->name() == "device_threshold_test");
        CHECK(rule->rule_class() == "");
        CHECK(rule->element() == "ggg");
        CHECK(rule->getNeededTopics() == std::vector<std::string>{"device_metric@ggg"});

        std::map<std::string, double> vars = rule->globalVariables();
        CHECK(vars.size() == 4);
        CHECK(double_equals(vars[low_critical], 30.0));
        CHECK(double_equals(vars[low_warning], 40.0));
        CHECK(double_equals(vars[high_warning], 50.0));
        CHECK(double_equals(vars[high_critical], 60.0));

        Outcome oc;
        oc = rule->outcome(low_warning);
        CHECK(oc._description == "wow LOW warning description");
        CHECK(oc._severity == "WARNING");
        CHECK(oc._actions == action_EMAIL);
        oc = rule->outcome(low_critical);
        CHECK(oc._description == "WOW low critical description");
        CHECK(oc._severity == "CRITICAL");
        CHECK(oc._actions == action_EMAIL_SMS);
        oc = rule->outcome(high_warning);
        CHECK(oc._description == "wow high WARNING description");
        CHECK(oc._severity == "WARNING");
        CHECK(oc._actions == action_EMAIL);
        oc = rule->outcome(high_critical);
        CHECK(oc._description == "wow high critical DESCTIPRION");
        CHECK(oc._severity == "CRITICAL");
        CHECK(oc._actions == action_EMAIL);
    }

    {
        std::string json(readFile(dir + "complexthreshold.rule"));
        REQUIRE(readRule(json, rule) == 0);

        CHECK(rule->whoami() == "threshold");
        CHECK(rule->name() == "complexthreshold");
        CHECK(rule->rule_class() == "example class");
        CHECK(rule->element() == "fff");
        std::vector<std::string> topics = {"abc@fff1", "abc@fff2"};
        CHECK(rule->getNeededTopics() == topics);

        std::map<std::string, double> vars = rule->globalVariables();
        CHECK(vars.size() == 4);
        CHECK(double_equals(vars[low_critical], 30.0));
        CHECK(double_equals(vars[low_warning], 40.0));
        CHECK(double_equals(vars[high_warning], 50.0));
        CHECK(double_equals(vars[high_critical], 60.0));

        Outcome oc;
        oc = rule->outcome(low_warning);
        CHECK(oc._description == "wow LOW warning description");
        CHECK(oc._severity == "WARNING");
        CHECK(oc._actions == action_EMAIL);
        oc = rule->outcome(low_critical);
        CHECK(oc._description == "WOW low critical description");
        CHECK(oc._severity == "CRITICAL");
        CHECK(oc._actions == action_EMAIL_SMS);
        oc = rule->outcome(high_warning);
        CHECK(oc._description == "wow high WARNING description");
        CHECK(oc._severity == "WARNING");
        CHECK(oc._actions == action_EMAIL);
        oc = rule->outcome(high_critical);
        CHECK(oc._description == "wow high critical DESCTIPRION");
        CHECK(oc._severity == "CRITICAL");
        CHECK(oc._actions == action_EMAIL);
    }

    {
        std::string json(readFile(dir + "single.rule"));
        REQUIRE(readRule(json, rule) == 0);

        CHECK(rule->whoami() == "single");
        CHECK(rule->name() == "single");
        CHECK(rule->rule_class() == "");
        CHECK(rule->element() == "aaa");
        std::vector<std::string> topics = {"abc@sss1", "abc@sss2"};
        CHECK(rule->getNeededTopics() == topics);

        std::map<std::string, double> vars = rule->globalVariables();
        CHECK(vars.size() == 2);
        CHECK(double_equals(vars["a1"], 2.0));
        CHECK(double_equals(vars["a2"], -3.0));
        CHECK(double_equals(vars[low_critical], 0.0));
        CHECK(double_equals(vars[low_warning], 0.0));
        CHECK(double_equals(vars[high_warning], 0.0));
        CHECK(double_equals(vars[high_critical], 0.0));

        Outcome oc;
        oc = rule->outcome(high_warning);
        CHECK(oc._description == "RES r2");
        CHECK(oc._severity == "WARNING");
        CHECK(oc._actions == action_EMAIL_GPO);
        oc = rule->outcome(high_critical);
        CHECK(oc._description == "RES r1");
        CHECK(oc._severity == "CRITICAL");
        CHECK(oc._actions == action_EMAIL_SMS);

        auto luaRule = std::unique_ptr<LuaRule>(dynamic_cast<LuaRule*>(rule.release()));
        REQUIRE(luaRule);
        CHECK(luaRule->code() ==
               "function main(abc_sss1, abc_sss2) local new_value = abc_sss1*a1 + abc_sss2*a2 if  ( new_value > 0 ) "
               "then return HIGH_WARNING end if ( new_value < -10 ) then return HIGH_CRITICAL end return OK end");
    }
}

TEST_CASE("alertconfiguration readConfiguration")
{
    {
        AlertConfiguration ac;
        ac.setPath("./tmp/fake"); // bad path
        CHECK(ac.getPersistencePath() == "./tmp/fake/");

        std::set<std::string> topics;
        REQUIRE_NOTHROW((topics = ac.readConfiguration()));
        CHECK(topics.size() == 0);
        CHECK(ac.size() == 0);
    }

    {
        const std::string dir("test/testrules/");
        logDebug("dir: {}", dir);

        AlertConfiguration ac;
        ac.setPath(dir);

        std::set<std::string> topics;
        REQUIRE_NOTHROW((topics = ac.readConfiguration()));
        CHECK(topics.size() != 0);
        CHECK(ac.size() != 0);

        logDebug("== ac topics:"); for (const auto& it : topics) { logDebug("{}", it); }
        logDebug("== ac alerts:"); for (const auto& it : ac) { logDebug("{}", it.first); }
    }
}
