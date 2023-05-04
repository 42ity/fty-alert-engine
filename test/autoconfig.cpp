#include <catch2/catch.hpp>

#include "src/autoconfig.h"
#include "src/templateruleconfigurator.h"
#include "cxxtools/serializationinfo.h"
#include <fty_log.h>
#include <fty_common_json.h>

#define SELFTEST_DIR_RO "."

TEST_CASE("autoconfig_test")
{
    // Basic test: try to load JSON rules to see if these are well formed
    // This will avoid regression in the future, since fty-alert-engine only
    // stores this to provide to fty-alert-flexible, which is in charge of the
    // actual parsing
    // Ref: https://github.com/42ity/fty-alert-engine/pull/175
    // Note: we simply try to deserialize using cxxtools, unlike fty-alert-flexible
    // which uses vsjson!

    ManageFtyLog::setInstanceFtylog("autoconfig_test", FTY_COMMON_LOGGING_DEFAULT_CFG);

    // template paths (src/ and tests/)
    std::vector<std::string> testVector = {
        SELFTEST_DIR_RO "/../src/rule_templates/",
        SELFTEST_DIR_RO "/test/templates/"
    };

    for (auto& templatePath : testVector) {
        Autoconfig::RuleFilePath = templatePath;

        TemplateRuleConfigurator templateRuleConfigurator;
        std::vector<std::pair<std::string, std::string>> templates = templateRuleConfigurator.loadAllTemplates();

        printf("number of template rules = '%zu'\n", templates.size());

        REQUIRE(templates.size() != 0);

        for (const auto& templat : templates) {
            // read json and deserialize it
            std::string ruleFilename = templatePath + templat.first;
            printf("JSON parse %s\n", ruleFilename.c_str());

            try {
                cxxtools::SerializationInfo si;
                JSON::readFromFile(ruleFilename, si);

                REQUIRE(si.memberCount() == 1);

                auto ruleType = si.getMember(0).name();
                printf("ruleType: %s\n", ruleType.c_str());
                REQUIRE((ruleType == "threshold" || ruleType == "single" || ruleType == "flexible"));
            }
            catch (const std::exception& e) {
                printf("JSON parse failed ('%s', e: '%s')\n", ruleFilename.c_str(), e.what());
                CHECK(0 == 1);
            }
        }
    }
}
