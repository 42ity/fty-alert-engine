#include <catch2/catch.hpp>

#include "src/autoconfig.h"
#include "src/templateruleconfigurator.h"

#include <cxxtools/serializationinfo.h>
#include <fty_common_json.h>
#include <fty_log.h>

#define SELFTEST_DIR_RO "."

TEST_CASE("autoconfig loadAllTemplates")
{
    // Basic test: try to load JSON rules to see if these are well formed
    // This will avoid regression in the future, since fty-alert-engine only
    // stores this to provide to fty-alert-flexible, which is in charge of the
    // actual parsing

    ManageFtyLog::setInstanceFtylog("autoconfig_test", FTY_COMMON_LOGGING_DEFAULT_CFG);

    {
        char cwd[PATH_MAX];
        if (getcwd(cwd, sizeof(cwd)) != NULL) {
           printf("== Current working dir: %s\n", cwd);
       }
    }

    // template paths (src/ and tests/)
    std::vector<std::string> testVector = {
        SELFTEST_DIR_RO "/../../lib/rule_templates/",
        SELFTEST_DIR_RO "/test/templates/"
    };

    for (auto& templatePath : testVector) {
        Autoconfig::RuleFilePath = templatePath;

        TemplateRuleConfigurator TRC;
        std::vector<std::pair<std::string, std::string>> templates = TRC.loadAllTemplates();

        printf("%s : number of template rules = '%zu'\n", templatePath.c_str(), templates.size());

        REQUIRE(templates.size() != 0);

        for (const auto& templat : templates) {
            // read json and deserialize it
            std::string ruleFilename = templatePath + templat.first;
            printf("JSON parse %s\n", ruleFilename.c_str());

            // read the file directly, check json memberCnt and rule type
            try {
                cxxtools::SerializationInfo si;
                JSON::readFromFile(ruleFilename, si);

                REQUIRE(si.memberCount() == 1);

                auto ruleType = si.getMember(0).name();
                printf("1/ ruleType: %s\n", ruleType.c_str());
                REQUIRE((ruleType == "threshold" || ruleType == "single" || ruleType == "flexible"));
            }
            catch (const std::exception& e) {
                printf("JSON parse failed ('%s', e: '%s')\n", ruleFilename.c_str(), e.what());
                REQUIRE(false);
            }

            // parse json from string, check memberCnt and rule type
            try {
                const std::string json{templat.second};
                cxxtools::SerializationInfo si;
                JSON::readFromString(json, si);

                REQUIRE(si.memberCount() == 1);

                auto ruleType = si.getMember(0).name();
                printf("2/ ruleType: %s\n", ruleType.c_str());
                REQUIRE((ruleType == "threshold" || ruleType == "single" || ruleType == "flexible"));
            }
            catch (const std::exception& e) {
                printf("JSON parse failed ('%s', e: '%s')\n", ruleFilename.c_str(), e.what());
                REQUIRE(false);
            }
        }
    }
}
