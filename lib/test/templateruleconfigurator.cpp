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

#define SELFTEST_DIR_RO "."

TEST_CASE("templateruleconfigurator")
{
    TemplateRuleConfigurator TRC;

    SECTION("default+safe")
    {
        CHECK(TRC.configure("asset_name", AutoConfigurationInfo(), "logical_asset", NULL) == false);
        CHECK(TRC.isApplicable(AutoConfigurationInfo()) == false);
        CHECK(TRC.sendAddRule("hello world", NULL) == false);

        Autoconfig::RuleFilePath = "";
        CHECK(TRC.loadAllTemplates().empty());

        Autoconfig::RuleFilePath = "/fake";
        CHECK(TRC.loadAllTemplates().empty());

        Autoconfig::RuleFilePath = SELFTEST_DIR_RO "/../../lib/rule_templates/";
        CHECK(!TRC.loadAllTemplates().empty());
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
