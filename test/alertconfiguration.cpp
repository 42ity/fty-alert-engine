#include <catch2/catch.hpp>
#include <fty_log.h>
#include "src/rule.h"
#include "src/alertconfiguration.h"

static bool double_equals(double d1, double d2)
{
    return std::abs(d1 - d2) < std::numeric_limits<double>::epsilon() * (std::abs(d1 + d2) + 1);
}

TEST_CASE("alertconfiguration test")
{
    setenv("BIOS_LOG_PATTERN", "%D %c [%t] -%-5p- %M (%l) %m%n", 1);
    ManageFtyLog::setInstanceFtylog("fty-alert-configuration");

    const std::string        dir("test/testrules/");
    std::unique_ptr<Rule>    rule;
    std::vector<std::string> action_EMAIL     = {"EMAIL"};
    std::vector<std::string> action_EMAIL_SMS = {"EMAIL", "SMS"};

    {
        std::ifstream f(dir + "pattern.rule");
        REQUIRE(readRule(f, rule) == 0);
        CHECK(rule->whoami() == "pattern");
        CHECK(rule->name() == "warranty2");
        CHECK(rule->rule_class() == "");
        CHECK(rule->_element == "");
        CHECK(rule->getNeededTopics() == std::vector<std::string>{"^end_warranty_date@.+"});
        std::map<std::string, double> vars = rule->getGlobalVariables();
        CHECK(double_equals(vars["low_warning"], 60.0));
        CHECK(double_equals(vars["low_critical"], 10.0));
        CHECK(double_equals(vars["high_warning"], 0.0));
        CHECK(double_equals(vars["high_critical"], 0.0));

        CHECK(rule->_outcomes["low_warning"]._description == "Warranty for device will expire in less than 60 days");
        CHECK(rule->_outcomes["low_warning"]._severity == "WARNING");
        CHECK(rule->_outcomes["low_warning"]._actions == action_EMAIL);

        CHECK(rule->_outcomes["low_critical"]._description == "Warranty for device will expire in less than 10 days");
        CHECK(rule->_outcomes["low_critical"]._severity == "CRITICAL");
        CHECK(rule->_outcomes["low_critical"]._actions == action_EMAIL);

        CHECK(rule->code() ==
               "function main(value) if( value <= low_critical ) then return LOW_CRITICAL end if ( value <= "
               "low_warning ) then return LOW_WARNING end return OK end");
    }
    {
        std::ifstream f(dir + "simplethreshold.rule");
        REQUIRE(readRule(f, rule) == 0);
        CHECK(rule->whoami() == "threshold");
        CHECK(rule->name() == "simplethreshold");
        CHECK(rule->rule_class() == "example class");
        CHECK(rule->_element == "fff");
        CHECK(rule->getNeededTopics() == std::vector<std::string>{"abc@fff"});
        std::map<std::string, double> vars = rule->getGlobalVariables();
        CHECK(double_equals(vars["low_warning"], 40.0));
        CHECK(double_equals(vars["low_critical"], 30.0));
        CHECK(double_equals(vars["high_warning"], 50.0));
        CHECK(double_equals(vars["high_critical"], 60.0));

        CHECK(rule->_outcomes["low_warning"]._description == "wow LOW warning description");
        CHECK(rule->_outcomes["low_warning"]._severity == "WARNING");
        CHECK(rule->_outcomes["low_warning"]._actions == action_EMAIL);

        CHECK(rule->_outcomes["low_critical"]._description == "WOW low critical description");
        CHECK(rule->_outcomes["low_critical"]._severity == "CRITICAL");
        CHECK(rule->_outcomes["low_critical"]._actions == action_EMAIL_SMS);

        CHECK(rule->_outcomes["high_warning"]._description == "wow high WARNING description");
        CHECK(rule->_outcomes["high_warning"]._severity == "WARNING");
        CHECK(rule->_outcomes["high_warning"]._actions == action_EMAIL);

        CHECK(rule->_outcomes["high_critical"]._description == "wow high critical DESCTIPRION");
        CHECK(rule->_outcomes["high_critical"]._severity == "CRITICAL");
        CHECK(rule->_outcomes["high_critical"]._actions == action_EMAIL);
    }
    {
        std::ifstream f(dir + "devicethreshold.rule");
        REQUIRE(readRule(f, rule) == 0);
        CHECK(rule->whoami() == "threshold");
        CHECK(rule->name() == "device_threshold_test");
        CHECK(rule->rule_class() == "");
        CHECK(rule->_element == "ggg");
        CHECK(rule->getNeededTopics().size() == 0);
        std::map<std::string, double> vars = rule->getGlobalVariables();
        CHECK(double_equals(vars["low_warning"], 40.0));
        CHECK(double_equals(vars["low_critical"], 30.0));
        CHECK(double_equals(vars["high_warning"], 50.0));
        CHECK(double_equals(vars["high_critical"], 60.0));

        CHECK(rule->_outcomes["low_warning"]._description == "wow LOW warning description");
        CHECK(rule->_outcomes["low_warning"]._severity == "WARNING");
        CHECK(rule->_outcomes["low_warning"]._actions == action_EMAIL);

        CHECK(rule->_outcomes["low_critical"]._description == "WOW low critical description");
        CHECK(rule->_outcomes["low_critical"]._severity == "CRITICAL");
        CHECK(rule->_outcomes["low_critical"]._actions == action_EMAIL_SMS);

        CHECK(rule->_outcomes["high_warning"]._description == "wow high WARNING description");
        CHECK(rule->_outcomes["high_warning"]._severity == "WARNING");
        CHECK(rule->_outcomes["high_warning"]._actions == action_EMAIL);

        CHECK(rule->_outcomes["high_critical"]._description == "wow high critical DESCTIPRION");
        CHECK(rule->_outcomes["high_critical"]._severity == "CRITICAL");
        CHECK(rule->_outcomes["high_critical"]._actions == action_EMAIL);
    }
    {
        std::ifstream f(dir + "complexthreshold.rule");
        REQUIRE(readRule(f, rule) == 0);
        CHECK(rule->whoami() == "threshold");
        CHECK(rule->name() == "complexthreshold");
        CHECK(rule->rule_class() == "example class");
        CHECK(rule->_element == "fff");
        std::vector<std::string> topics = {"abc@fff1", "abc@fff2"};
        CHECK(rule->getNeededTopics() == topics);
        std::map<std::string, double> vars = rule->getGlobalVariables();
        CHECK(double_equals(vars["low_warning"], 40.0));
        CHECK(double_equals(vars["low_critical"], 30.0));
        CHECK(double_equals(vars["high_warning"], 50.0));
        CHECK(double_equals(vars["high_critical"], 60.0));

        CHECK(rule->_outcomes["low_warning"]._description == "wow LOW warning description");
        CHECK(rule->_outcomes["low_warning"]._severity == "WARNING");
        CHECK(rule->_outcomes["low_warning"]._actions == action_EMAIL);

        CHECK(rule->_outcomes["low_critical"]._description == "WOW low critical description");
        CHECK(rule->_outcomes["low_critical"]._severity == "CRITICAL");
        CHECK(rule->_outcomes["low_critical"]._actions == action_EMAIL_SMS);

        CHECK(rule->_outcomes["high_warning"]._description == "wow high WARNING description");
        CHECK(rule->_outcomes["high_warning"]._severity == "WARNING");
        CHECK(rule->_outcomes["high_warning"]._actions == action_EMAIL);

        CHECK(rule->_outcomes["high_critical"]._description == "wow high critical DESCTIPRION");
        CHECK(rule->_outcomes["high_critical"]._severity == "CRITICAL");
        CHECK(rule->_outcomes["high_critical"]._actions == action_EMAIL);
    }
    {
        std::ifstream f(dir + "single.rule");
        REQUIRE(readRule(f, rule) == 0);
        CHECK(rule->whoami() == "single");
        CHECK(rule->name() == "single");
        CHECK(rule->rule_class() == "");
        CHECK(rule->_element == "aaa");
        std::vector<std::string> topics = {"abc@sss1", "abc@sss2"};
        CHECK(rule->getNeededTopics() == topics);
        std::map<std::string, double> vars = rule->getGlobalVariables();
        CHECK(double_equals(vars["a1"], 2.0));
        CHECK(double_equals(vars["a2"], -3.0));
        CHECK(double_equals(vars["low_warning"], 0.0));
        CHECK(double_equals(vars["low_critical"], 0.0));
        CHECK(double_equals(vars["high_warning"], 0.0));
        CHECK(double_equals(vars["high_critical"], 0.0));

        CHECK(rule->_outcomes["high_warning"]._description == "RES r2");
        CHECK(rule->_outcomes["high_warning"]._severity == "WARNING");
        std::vector<std::string> action_EMAIL_GPO = {"EMAIL", "GPO_INTERACTION:gpo-42:open"};
        CHECK(rule->_outcomes["high_warning"]._actions == action_EMAIL_GPO);

        CHECK(rule->_outcomes["high_critical"]._description == "RES r1");
        CHECK(rule->_outcomes["high_critical"]._severity == "CRITICAL");
        CHECK(rule->_outcomes["high_critical"]._actions == action_EMAIL_SMS);

        CHECK(rule->code() ==
               "function main(abc_sss1, abc_sss2) local new_value = abc_sss1*a1 + abc_sss2*a2 if  ( new_value > 0 ) "
               "then return HIGH_WARNING end if ( new_value < -10 ) then return HIGH_CRITICAL end return OK end");
    }
}
