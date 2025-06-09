#include <catch2/catch.hpp>
#include "src/templateruleconfigurator.h"

TEST_CASE("templateruleconfigurator test")
{
    TemplateRuleConfigurator TRC;

    SECTION("default+safe")
    {
        CHECK(TRC.configure("asset_name", AutoConfigurationInfo(), "logical_asset", NULL) == false);
        CHECK(TRC.isApplicable(AutoConfigurationInfo()) == false);
        CHECK(TRC.sendAddRule("hello world", NULL) == false);

        Autoconfig::RuleFilePath = "";
        CHECK(TRC.loadAllTemplates().empty());
    }

    SECTION("sendAddRule mlm")
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
