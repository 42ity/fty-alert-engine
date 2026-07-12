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
#include "src/templateruleconfigurator.h"
#include "src/misc/json.h"
#include <fty_common_json.h>
#include <cxxtools/serializationinfo.h>
#include <iostream>

#define SELFTEST_DIR_RO "."

TEST_CASE("templateruleconfigurator")
{
    TemplateRuleConfigurator TRC;

    SECTION("default+safe")
    {
        AutoconfigSettings settings;

        CHECK(TRC.configure("asset_name", AutoConfigurationInfo(), settings, "logical_asset", NULL) == false);
        CHECK(TRC.isApplicable(AutoConfigurationInfo()) == false);
        CHECK(TRC.sendAddRule("hello world", NULL) == false);

        Autoconfig::TemplatesDir = "";
        CHECK(TRC.loadAllTemplates(settings).empty());

        Autoconfig::TemplatesDir = "/fake";
        CHECK(TRC.loadAllTemplates(settings).empty());

        Autoconfig::TemplatesDir = SELFTEST_DIR_RO "/../../lib/rule_templates/";
        CHECK(!TRC.loadAllTemplates(settings).empty());
    }

    SECTION("sendAddRule malamute")
    {
        const char* TEST_ENDPOINT = "inproc://ruleconfigurator-test";

        zactor_t* server = zactor_new(mlm_server, static_cast<void*>(const_cast<char*>("Malamute_ruleconfigurator_test")));
        REQUIRE(server);
        zstr_sendx(server, "BIND", TEST_ENDPOINT, NULL);

        mlm_client_t* client = mlm_client_new();
        REQUIRE(client);
        mlm_client_connect(client, TEST_ENDPOINT, 1000, "client-ruleconfigurator-test");

        mlm_client_t* autoconf = mlm_client_new();
        REQUIRE(autoconf);
        Autoconfig::AlertEngineName = "autoconf-ruleconfigurator-test";
        mlm_client_connect(autoconf, TEST_ENDPOINT, 1000, "autoconf-ruleconfigurator-test");

        const char* theRuleJsonpayload = "theRuleJsonPayload";
        CHECK(TRC.sendAddRule(theRuleJsonpayload, client) == true);

        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(autoconf), NULL);
        REQUIRE(poller);
        void* which = zpoller_wait(poller, 5000);
        CHECK(which != NULL);
        zpoller_destroy(&poller);

        zmsg_t* msg = mlm_client_recv(autoconf);
        CHECK(msg);
        char* s = zmsg_popstr(msg);
        CHECK((s && streq(s, "ADD")));
        zstr_free(&s);
        s = zmsg_popstr(msg);
        CHECK((s && streq(s, theRuleJsonpayload)));
        zstr_free(&s);
        s = zmsg_popstr(msg);
        CHECK(!s);
        zstr_free(&s);
        zmsg_destroy(&msg);

        mlm_client_destroy(&client);
        mlm_client_destroy(&autoconf);
        zactor_destroy(&server);
    }
}

TEST_CASE("templateruleconfigurator settings voltageStandard")
{
    //templateruleconfigurator.cc::applySettingsOnTemplate()

    for (const auto& vs : {"EUROPE", "USA", "AUSTRALIA", "EUROPE_208"})
    {
        AutoconfigSettings settings;
        settings.setVoltageStandard(vs);
        REQUIRE(settings.voltageStandard() == vs);

        std::cout << "=== voltageStandard = " << settings.voltageStandard() << std::endl;

        TemplateRuleConfigurator TRC;
        Autoconfig::TemplatesDir = SELFTEST_DIR_RO "/../../lib/rule_templates/";
        auto templates = TRC.loadAllTemplates(settings);
        CHECK(!templates.empty());

        for (const auto& it : templates) {
            if (it.first.find("voltage.input_") == 0) {
                std::cout << "=== " << it.first << std::endl << it.second << std::endl;

                cxxtools::SerializationInfo si;
                JSON::readFromString(it.second /*json*/, si);
                auto root{si.findMember("threshold")};
                auto values{root ? root->findMember("values") : nullptr};
                REQUIRE(values);

                auto m = JSON::getMapDouble(values);
                CHECK(m.size() == 4);

                // EU thresholds embeded by the voltage.input template rules (lib/rule_templates/),
                // other thresholds are defined by applySettingsOnTemplate()
                if (settings.voltageStandard() == "EUROPE") {
                    CHECK(m["low_critical"]  == 210);
                    CHECK(m["low_warning"]   == 215);
                    CHECK(m["high_warning"]  == 265);
                    CHECK(m["high_critical"] == 276);
                }
                else if (settings.voltageStandard() == "USA") {
                    CHECK(m["low_critical"]  == 110);
                    CHECK(m["low_warning"]   == 115);
                    CHECK(m["high_warning"]  == 125);
                    CHECK(m["high_critical"] == 130);
                }
                else if (settings.voltageStandard() == "AUSTRALIA") {
                    CHECK(m["low_critical"]  == 210);
                    CHECK(m["low_warning"]   == 215);
                    CHECK(m["high_warning"]  == 245);
                    CHECK(m["high_critical"] == 250);
                }
                else if (settings.voltageStandard() == "EUROPE_208") {
                    CHECK(m["low_critical"]  == 360);
                    CHECK(m["low_warning"]   == 385);
                    CHECK(m["high_warning"]  == 415);
                    CHECK(m["high_critical"] == 430);
                }
                else {
                    REQUIRE(false);
                }
            }
        }
    }
}
