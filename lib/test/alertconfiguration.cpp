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

#include <fty_log.h>
#include <istream>

static bool double_equals(double d1, double d2)
{
    return std::abs(d1 - d2) < std::numeric_limits<double>::epsilon() * (std::abs(d1 + d2) + 1);
}

static std::string readFile(const std::string& path)
{
    std::ifstream ifs{path};
    const std::string buf{std::istreambuf_iterator<char>(ifs), {}};
    logDebug("path {}\n{}", path, buf);
    return buf;
}

TEST_CASE("rule outcome tokens")
{
    REQUIRE(RULE_RESULT_LOW_CRITICAL == -2);
    REQUIRE(RULE_RESULT_UNKNOWN == 3);

    CHECK(Rule::resultToString(RULE_RESULT_LOW_CRITICAL - 1) == Rule::resultToString(RULE_RESULT_UNKNOWN));
    CHECK(Rule::resultToString(RULE_RESULT_UNKNOWN + 1) == Rule::resultToString(RULE_RESULT_UNKNOWN));

    CHECK(Rule::resultToInt("") == RULE_RESULT_UNKNOWN);
    CHECK(Rule::resultToInt("hello") == RULE_RESULT_UNKNOWN);

    for (const auto& r : {
        RULE_RESULT_LOW_CRITICAL,
        RULE_RESULT_LOW_WARNING,
        RULE_RESULT_OK,
        RULE_RESULT_HIGH_WARNING,
        RULE_RESULT_HIGH_CRITICAL,
        RULE_RESULT_UNKNOWN
    }
    ) {
        CHECK(r == Rule::resultToInt(Rule::resultToString(r)));
    }

    for (const auto& s : {
        "low_critical",
        "low_warning",
        "ok",
        "high_warning",
        "high_critical",
        "unknown"
    }
    ) {
        CHECK(s == Rule::resultToString(Rule::resultToInt(s)));
    }
}

TEST_CASE("alertconfiguration")
{
    setenv("BIOS_LOG_PATTERN", "%D %c [%t] -%-5p- %M (%l) %m%n", 1);
    ManageFtyLog::setInstanceFtylog("fty-alert-configuration");

    const std::string        dir("test/testrules/");
    std::unique_ptr<Rule>    rule;
    std::vector<std::string> action_EMAIL     = {"EMAIL"};
    std::vector<std::string> action_EMAIL_SMS = {"EMAIL", "SMS"};

    {
        std::string json;

        json = "{}";
        REQUIRE(readRule(json, rule) == 1); // no member

        json = "{ \"member0\":{}, \"member1\":{} }";
        REQUIRE(readRule(json, rule) == 1); // multi member

        json = "{ \"member\":{";
        REQUIRE(readRule(json, rule) == 1); // invalid

        json = "{ \"hello\":{} }";
        REQUIRE(readRule(json, rule) == 1); // unrecognized
    }

    {
        AlertConfiguration ac;
        std::set<std::string> topics;
        ac.setPath("./tmp/fake");
        REQUIRE_NOTHROW((topics = ac.readConfiguration()));
        CHECK(topics.size() == 0);
        CHECK(ac.size() == 0);
    }

    {
        std::string json(readFile(dir + "pattern.rule"));
        REQUIRE(readRule(json, rule) == 0);

        CHECK(rule->whoami() == "pattern");
        CHECK(rule->name() == "warranty2");
        CHECK(rule->rule_class() == "");
        CHECK(rule->element() == "");
        CHECK(rule->getNeededTopics() == std::vector<std::string>{"^end_warranty_date@.+"});
        std::map<std::string, double> vars = rule->globalVariables();
        CHECK(double_equals(vars["low_warning"], 60.0));
        CHECK(double_equals(vars["low_critical"], 10.0));
        CHECK(double_equals(vars["high_warning"], 0.0));
        CHECK(double_equals(vars["high_critical"], 0.0));

        CHECK(rule->outcome("low_warning")._description == "Warranty for device will expire in less than 60 days");
        CHECK(rule->outcome("low_warning")._severity == "WARNING");
        CHECK(rule->outcome("low_warning")._actions == action_EMAIL);

        CHECK(rule->outcome("low_critical")._description == "Warranty for device will expire in less than 10 days");
        CHECK(rule->outcome("low_critical")._severity == "CRITICAL");
        CHECK(rule->outcome("low_critical")._actions == action_EMAIL);

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
        CHECK(double_equals(vars["low_warning"], 40.0));
        CHECK(double_equals(vars["low_critical"], 30.0));
        CHECK(double_equals(vars["high_warning"], 50.0));
        CHECK(double_equals(vars["high_critical"], 60.0));

        CHECK(rule->outcome("low_warning")._description == "wow LOW warning description");
        CHECK(rule->outcome("low_warning")._severity == "WARNING");
        CHECK(rule->outcome("low_warning")._actions == action_EMAIL);

        CHECK(rule->outcome("low_critical")._description == "WOW low critical description");
        CHECK(rule->outcome("low_critical")._severity == "CRITICAL");
        CHECK(rule->outcome("low_critical")._actions == action_EMAIL_SMS);

        CHECK(rule->outcome("high_warning")._description == "wow high WARNING description");
        CHECK(rule->outcome("high_warning")._severity == "WARNING");
        CHECK(rule->outcome("high_warning")._actions == action_EMAIL);

        CHECK(rule->outcome("high_critical")._description == "wow high critical DESCTIPRION");
        CHECK(rule->outcome("high_critical")._severity == "CRITICAL");
        CHECK(rule->outcome("high_critical")._actions == action_EMAIL);
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
        CHECK(double_equals(vars["low_warning"], 40.0));
        CHECK(double_equals(vars["low_critical"], 30.0));
        CHECK(double_equals(vars["high_warning"], 50.0));
        CHECK(double_equals(vars["high_critical"], 60.0));

        CHECK(rule->outcome("low_warning")._description == "wow LOW warning description");
        CHECK(rule->outcome("low_warning")._severity == "WARNING");
        CHECK(rule->outcome("low_warning")._actions == action_EMAIL);

        CHECK(rule->outcome("low_critical")._description == "WOW low critical description");
        CHECK(rule->outcome("low_critical")._severity == "CRITICAL");
        CHECK(rule->outcome("low_critical")._actions == action_EMAIL_SMS);

        CHECK(rule->outcome("high_warning")._description == "wow high WARNING description");
        CHECK(rule->outcome("high_warning")._severity == "WARNING");
        CHECK(rule->outcome("high_warning")._actions == action_EMAIL);

        CHECK(rule->outcome("high_critical")._description == "wow high critical DESCTIPRION");
        CHECK(rule->outcome("high_critical")._severity == "CRITICAL");
        CHECK(rule->outcome("high_critical")._actions == action_EMAIL);
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
        CHECK(double_equals(vars["low_warning"], 40.0));
        CHECK(double_equals(vars["low_critical"], 30.0));
        CHECK(double_equals(vars["high_warning"], 50.0));
        CHECK(double_equals(vars["high_critical"], 60.0));

        CHECK(rule->outcome("low_warning")._description == "wow LOW warning description");
        CHECK(rule->outcome("low_warning")._severity == "WARNING");
        CHECK(rule->outcome("low_warning")._actions == action_EMAIL);

        CHECK(rule->outcome("low_critical")._description == "WOW low critical description");
        CHECK(rule->outcome("low_critical")._severity == "CRITICAL");
        CHECK(rule->outcome("low_critical")._actions == action_EMAIL_SMS);

        CHECK(rule->outcome("high_warning")._description == "wow high WARNING description");
        CHECK(rule->outcome("high_warning")._severity == "WARNING");
        CHECK(rule->outcome("high_warning")._actions == action_EMAIL);

        CHECK(rule->outcome("high_critical")._description == "wow high critical DESCTIPRION");
        CHECK(rule->outcome("high_critical")._severity == "CRITICAL");
        CHECK(rule->outcome("high_critical")._actions == action_EMAIL);
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
        CHECK(double_equals(vars["a1"], 2.0));
        CHECK(double_equals(vars["a2"], -3.0));
        CHECK(double_equals(vars["low_warning"], 0.0));
        CHECK(double_equals(vars["low_critical"], 0.0));
        CHECK(double_equals(vars["high_warning"], 0.0));
        CHECK(double_equals(vars["high_critical"], 0.0));

        CHECK(rule->outcome("high_warning")._description == "RES r2");
        CHECK(rule->outcome("high_warning")._severity == "WARNING");
        std::vector<std::string> action_EMAIL_GPO = {"EMAIL", "GPO_INTERACTION:gpo-42:open"};
        CHECK(rule->outcome("high_warning")._actions == action_EMAIL_GPO);

        CHECK(rule->outcome("high_critical")._description == "RES r1");
        CHECK(rule->outcome("high_critical")._severity == "CRITICAL");
        CHECK(rule->outcome("high_critical")._actions == action_EMAIL_SMS);

        auto luaRule = std::unique_ptr<LuaRule>(dynamic_cast<LuaRule*>(rule.release()));
        REQUIRE(luaRule);
        CHECK(luaRule->code() ==
               "function main(abc_sss1, abc_sss2) local new_value = abc_sss1*a1 + abc_sss2*a2 if  ( new_value > 0 ) "
               "then return HIGH_WARNING end if ( new_value < -10 ) then return HIGH_CRITICAL end return OK end");
    }
}
