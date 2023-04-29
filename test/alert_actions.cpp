#include "src/fty_alert_actions.h"
#include <catch2/catch.hpp>
#include <fty_log.h>

TEST_CASE("alert actions test - static")
{
    setenv("BIOS_LOG_PATTERN", "%D %c [%t] -%-5p- %M (%l) %m%n", 1);
    ManageFtyLog::setInstanceFtylog("fty-alert-actions");

    // test 1, simple create/destroy self test
    {
        log_debug("test 1");
        fty_alert_actions_t* self = fty_alert_actions_new();
        REQUIRE(self);
        self->integration_test = true;

        fty_alert_actions_destroy(&self);
    }

    // test 2, check alert interval calculation
    {
        log_debug("test 2");
        s_alert_cache* cache = static_cast<s_alert_cache*>(malloc(sizeof(s_alert_cache)));
        cache->alert_msg     = fty_proto_new(FTY_PROTO_ALERT);
        cache->related_asset = fty_proto_new(FTY_PROTO_ASSET);

        fty_proto_set_severity(cache->alert_msg, "CRITICAL");
        fty_proto_aux_insert(cache->related_asset, "priority", "%u", static_cast<unsigned int>(1));
        CHECK(5 * 60 * 1000 == get_alert_interval(cache));

        fty_proto_set_severity(cache->alert_msg, "WARNING");
        fty_proto_aux_insert(cache->related_asset, "priority", "%u", static_cast<unsigned int>(1));
        CHECK(1 * 60 * 60 * 1000 == get_alert_interval(cache));

        fty_proto_set_severity(cache->alert_msg, "INFO");
        fty_proto_aux_insert(cache->related_asset, "priority", "%u", static_cast<unsigned int>(1));
        CHECK(8 * 60 * 60 * 1000 == get_alert_interval(cache));

        fty_proto_set_severity(cache->alert_msg, "CRITICAL");
        fty_proto_aux_insert(cache->related_asset, "priority", "%u", static_cast<unsigned int>(3));
        CHECK(15 * 60 * 1000 == get_alert_interval(cache));

        fty_proto_set_severity(cache->alert_msg, "WARNING");
        fty_proto_aux_insert(cache->related_asset, "priority", "%u", static_cast<unsigned int>(3));
        CHECK(4 * 60 * 60 * 1000 == get_alert_interval(cache));

        fty_proto_set_severity(cache->alert_msg, "INFO");
        fty_proto_aux_insert(cache->related_asset, "priority", "%u", static_cast<unsigned int>(3));
        CHECK(24 * 60 * 60 * 1000 == get_alert_interval(cache));

        fty_proto_set_severity(cache->alert_msg, "CRITICAL");
        fty_proto_aux_insert(cache->related_asset, "priority", "%u", static_cast<unsigned int>(5));
        CHECK(15 * 60 * 1000 == get_alert_interval(cache));

        fty_proto_set_severity(cache->alert_msg, "WARNING");
        fty_proto_aux_insert(cache->related_asset, "priority", "%u", static_cast<unsigned int>(5));
        CHECK(4 * 60 * 60 * 1000 == get_alert_interval(cache));

        fty_proto_set_severity(cache->alert_msg, "INFO");
        fty_proto_aux_insert(cache->related_asset, "priority", "%u", static_cast<unsigned int>(5));
        CHECK(24 * 60 * 60 * 1000 == get_alert_interval(cache));

        fty_proto_destroy(&cache->alert_msg);
        fty_proto_destroy(&cache->related_asset);
        free(cache);
    }

    // test 3, simple create/destroy cache asset item test (asset found)
    {
        log_debug("test 3");
        fty_alert_actions_t* self = fty_alert_actions_new();
        REQUIRE(self);
        self->integration_test = true;

        fty_proto_t* asset = fty_proto_new(FTY_PROTO_ASSET);
        REQUIRE(asset);
        zhash_insert(self->assets_cache, "myasset-3", asset);

        fty_proto_t* msg = fty_proto_new(FTY_PROTO_ALERT);
        REQUIRE(msg);
        fty_proto_set_name(msg, "myasset-3");

        s_alert_cache* cache = new_alert_cache_item(self, msg);
        CHECK(cache);
        delete_alert_cache_item(cache);

        fty_alert_actions_destroy(&self);
        fty_proto_destroy(&asset);
    }

    // test 4, simple create/destroy cache alert item test (asset not found)
    {
        log_debug("test 4");
        fty_alert_actions_t* self = fty_alert_actions_new();
        REQUIRE(self);
        self->integration_test = true;

        fty_proto_t* msg = fty_proto_new(FTY_PROTO_ALERT);
        CHECK(msg);
        fty_proto_set_name(msg, "myasset-4");

        s_alert_cache* cache = new_alert_cache_item(self, msg);
        REQUIRE(cache);
        delete_alert_cache_item(cache);

        fty_alert_actions_destroy(&self);
    }

    // test 5, processing of alerts from stream
    {
        log_debug("test 5");
        fty_alert_actions_t* self = fty_alert_actions_new();
        REQUIRE(self);
        self->integration_test = true;

        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("SMS")));
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        zmsg_t* msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 120, "SOME_RULE", "SOME_ASSET",
            "ACTIVE", "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);

        // send an active alert
        s_handle_stream_deliver(self, &msg, "");
        zlist_destroy(&actions);

        // check the alert cache
        CHECK(zhash_size(self->alerts_cache) == 1);
        s_alert_cache* cached = static_cast<s_alert_cache*>(zhash_first(self->alerts_cache));
        CHECK(cached);
        CHECK(cached->alert_msg);

        fty_proto_t* alert  = cached->alert_msg;
        CHECK(streq(fty_proto_rule(alert), "SOME_RULE"));
        CHECK(streq(fty_proto_name(alert), "SOME_ASSET"));
        CHECK(streq(fty_proto_state(alert), "ACTIVE"));
        CHECK(streq(fty_proto_severity(alert), "CRITICAL"));
        CHECK(streq(fty_proto_description(alert), "ASDFKLHJH"));
        CHECK(streq(fty_proto_action_first(alert), "SMS"));
        CHECK(streq(fty_proto_action_next(alert), "EMAIL"));

        // resolve the alert
        actions = zlist_new();
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 120, "SOME_RULE", "SOME_ASSET",
            "RESOLVED", "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);
        zlist_destroy(&actions);

        s_handle_stream_deliver(self, &msg, "");

        // alert cache is now empty
        CHECK(zhash_size(self->alerts_cache) == 0);

        fty_alert_actions_destroy(&self);
    }

    // test 6, processing of assets from stream
    {
        log_debug("test 6");
        fty_alert_actions_t* self = fty_alert_actions_new();
        REQUIRE(self);
        self->integration_test = true;

        // send update
        zmsg_t* msg = fty_proto_encode_asset(NULL, "SOME_ASSET", FTY_PROTO_ASSET_OP_UPDATE, NULL);
        REQUIRE(msg);

        s_handle_stream_deliver(self, &msg, "");
        zclock_sleep(1000);

        // check the assets cache
        CHECK(zhash_size(self->assets_cache) == 1);
        fty_proto_t* cached = static_cast<fty_proto_t*>(zhash_first(self->assets_cache));
        CHECK(streq(fty_proto_operation(cached), FTY_PROTO_ASSET_OP_UPDATE));
        CHECK(streq(fty_proto_name(cached), "SOME_ASSET"));

        // delete asset
        msg = fty_proto_encode_asset(NULL, "SOME_ASSET", FTY_PROTO_ASSET_OP_DELETE, NULL);
        CHECK(msg);

        // CHECK ( zhash_size (self->assets_cache) != 0 );
        s_handle_stream_deliver(self, &msg, "");
        zclock_sleep(1000);

        CHECK(zhash_size(self->assets_cache) == 0);
        fty_alert_actions_destroy(&self);
    }

    // test 7, send asset + send an alert on the already known correct asset
    // + delete the asset + check that alert disappeared
    {
        log_debug("test 7");
        fty_alert_actions_t* self = fty_alert_actions_new();
        CHECK(self);
        self->integration_test = true;

        //      1. send asset info
        const char* asset_name = "ASSET1";
        zhash_t*    aux        = zhash_new();
        zhash_insert(aux, "priority", static_cast<void*>(const_cast<char*>("1")));
        zhash_t* ext = zhash_new();
        zhash_insert(ext, "contact_email", static_cast<void*>(const_cast<char*>("scenario1.email@eaton.com")));
        zhash_insert(ext, "contact_name", static_cast<void*>(const_cast<char*>("eaton Support team")));
        zhash_insert(ext, "name", static_cast<void*>(const_cast<char*>(asset_name)));
        zmsg_t* msg = fty_proto_encode_asset(aux, asset_name, FTY_PROTO_ASSET_OP_UPDATE, ext);
        zhash_destroy(&aux);
        zhash_destroy(&ext);
        REQUIRE(msg);

        s_handle_stream_deliver(self, &msg, "Asset message1");
        CHECK(zhash_size (self->assets_cache) == 1);

        //      2. send alert message
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("FAKE_ACTION")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 120, "NY_RULE", asset_name, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        zlist_destroy(&actions);
        REQUIRE(msg);

        std::string atopic = "NY_RULE/CRITICAL@" + std::string(asset_name);
        s_handle_stream_deliver(self, &msg, atopic.c_str());
        CHECK(zhash_size (self->alerts_cache) == 1);

        //      3. delete the asset
        msg = fty_proto_encode_asset(NULL, asset_name, FTY_PROTO_ASSET_OP_DELETE, NULL);
        REQUIRE(msg);
        s_handle_stream_deliver(self, &msg, "Asset message 1");
        CHECK(zhash_size (self->assets_cache) == 0);

        //      4. check that alert disappeared
        CHECK(zhash_size(self->alerts_cache) == 0);

        fty_alert_actions_destroy(&self);
    }
}

TEST_CASE("alert actions test - mlm")
{
    setenv("BIOS_LOG_PATTERN", "%D %c [%t] -%-5p- %M (%l) %m%n", 1);
    ManageFtyLog::setInstanceFtylog("fty-alert-actions");

    const char* TEST_ASSETS = "ASSETS-TEST"; // notification streams
    const char* TEST_ALERTS = "ALERTS-TEST";

    const char* FTY_EMAIL_AGENT_ADDRESS_TEST       = "fty-email-test";
    const char* FTY_SENSOR_GPIO_AGENT_ADDRESS_TEST = "fty-sensor-gpio-test";

    const int ALERT_TTL = 600; //seconds

    const char* TEST_ENDPOINT          = "inproc://fty-alert-actions-test";
    const char* FTY_ALERT_ACTIONS_TEST = "fty-alert-actions-test";

    zactor_t* server = zactor_new(mlm_server, static_cast<void*>(const_cast<char*>("Malamute_alert_actions_test")));
    REQUIRE(server);
    zstr_sendx(server, "BIND", TEST_ENDPOINT, NULL);

    zactor_t* alert_actions = zactor_new(fty_alert_actions, static_cast<void*>(const_cast<char*>(FTY_ALERT_ACTIONS_TEST)));
    REQUIRE(alert_actions);
    zstr_sendx(alert_actions, "CONNECT", TEST_ENDPOINT, NULL);
    zstr_sendx(alert_actions, "CONSUMER", TEST_ASSETS, ".*", NULL);
    zstr_sendx(alert_actions, "CONSUMER", TEST_ALERTS, ".*", NULL);
    // set integration_test to true (required by send_email()) + time periods shorten
    zstr_sendx(alert_actions, "INTEGRATION_TEST", "1", NULL);
    zstr_sendx(alert_actions, "TESTTIMEOUT", "1000", NULL);
    zstr_sendx(alert_actions, "TESTCHECKINTERVAL", "20000", NULL);
    zclock_sleep(500);

    mlm_client_t* asset_producer = mlm_client_new();
    REQUIRE(asset_producer);
    mlm_client_connect(asset_producer, TEST_ENDPOINT, 1000, "asset-producer-test");
    mlm_client_set_producer(asset_producer, TEST_ASSETS);

    mlm_client_t* alert_producer = mlm_client_new();
    REQUIRE(alert_producer);
    mlm_client_connect(alert_producer, TEST_ENDPOINT, 1000, "alert-producer-test");
    mlm_client_set_producer(alert_producer, TEST_ALERTS);

    mlm_client_t* email_client = mlm_client_new();
    REQUIRE(email_client);
    mlm_client_connect(email_client, TEST_ENDPOINT, 1000, FTY_EMAIL_AGENT_ADDRESS_TEST);

    mlm_client_t* gpio_client = mlm_client_new();
    REQUIRE(gpio_client);
    mlm_client_connect(gpio_client, TEST_ENDPOINT, 1000, FTY_SENSOR_GPIO_AGENT_ADDRESS_TEST);

    zclock_sleep(500);

    // test 8, send asset with e-mail + send an alert on the already known correct asset (with e-mail action)
    // + check that we send SENDMAIL_ALERT message
    SECTION("test 8")
    {
        log_debug("test 8");
        //      1. send asset info
        const char* asset_name = "ASSET";
        zhash_t*    aux        = zhash_new();
        zhash_insert(aux, "priority", static_cast<void*>(const_cast<char*>("1")));
        zhash_t* ext = zhash_new();
        zhash_insert(ext, "contact_email", static_cast<void*>(const_cast<char*>("scenario1.email@eaton.com")));
        zhash_insert(ext, "contact_name", static_cast<void*>(const_cast<char*>("eaton Support team")));
        zhash_insert(ext, "name", static_cast<void*>(const_cast<char*>(asset_name)));
        zmsg_t* msg = fty_proto_encode_asset(aux, asset_name, FTY_PROTO_ASSET_OP_UPDATE, ext);
        zhash_destroy(&aux);
        zhash_destroy(&ext);
        REQUIRE(msg);
        mlm_client_send(asset_producer, "Asset message1", &msg);
        zclock_sleep(1000);

        //      2. send alert message
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), ALERT_TTL, "NY_RULE", asset_name, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);
        std::string atopic = "NY_RULE/CRITICAL@" + std::string(asset_name);
        mlm_client_send(alert_producer, atopic.c_str(), &msg);
        zclock_sleep(1000);
        zlist_destroy(&actions);

        //      3. check that we send SENDMAIL_ALERT message to the correct MB
        msg = mlm_client_recv(email_client);
        REQUIRE(msg);
        CHECK(streq(mlm_client_subject(email_client), "SENDMAIL_ALERT"));
        char* zuuid_str = zmsg_popstr(msg);
        char* str       = zmsg_popstr(msg);
        CHECK(streq(str, "1"));
        zstr_free(&str);
        str = zmsg_popstr(msg);
        CHECK(streq(str, asset_name));
        zstr_free(&str);
        str = zmsg_popstr(msg);
        CHECK(streq(str, "scenario1.email@eaton.com"));
        zstr_free(&str);

        fty_proto_t* alert = fty_proto_decode(&msg);
        CHECK(streq(fty_proto_rule(alert), "NY_RULE"));
        CHECK(streq(fty_proto_name(alert), asset_name));
        CHECK(streq(fty_proto_state(alert), "ACTIVE"));
        CHECK(streq(fty_proto_severity(alert), "CRITICAL"));
        CHECK(streq(fty_proto_description(alert), "ASDFKLHJH"));
        CHECK(streq(fty_proto_action_first(alert), "EMAIL"));
        fty_proto_destroy(&alert);

        //       4. send the reply to unblock the actor
        zmsg_t* reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        mlm_client_sendto(email_client, FTY_ALERT_ACTIONS_TEST, "SENDMAIL_ALERT", NULL, 1000, &reply);

        zstr_free(&zuuid_str);
    }

    // test9, send asset + send an alert on the already known correct asset (with GPO action)
    // + check that we send GPO_INTERACTION message
    SECTION("test 9")
    {
        log_debug("test 9");
        //      1. send asset info
        const char* asset_name1 = "GPO1";
        zhash_t*    aux         = zhash_new();
        zhash_insert(aux, "priority", static_cast<void*>(const_cast<char*>("1")));
        zhash_t* ext = zhash_new();
        zhash_insert(ext, "contact_email", static_cast<void*>(const_cast<char*>("scenario1.email@eaton.com")));
        zhash_insert(ext, "contact_name", static_cast<void*>(const_cast<char*>("eaton Support team")));
        zhash_insert(ext, "name", static_cast<void*>(const_cast<char*>(asset_name1)));
        zmsg_t* msg = fty_proto_encode_asset(aux, asset_name1, FTY_PROTO_ASSET_OP_UPDATE, ext);
        zhash_destroy(&aux);
        zhash_destroy(&ext);
        REQUIRE(msg);
        mlm_client_send(asset_producer, "Asset message1", &msg);
        zclock_sleep(1000);

        //      2. send alert message
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("GPO_INTERACTION:gpo-1:open")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), ALERT_TTL, "NY_RULE1", asset_name1, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        zlist_destroy(&actions);
        REQUIRE(msg);
        std::string atopic = "NY_RULE1/CRITICAL@" + std::string(asset_name1);
        mlm_client_send(alert_producer, atopic.c_str(), &msg);

        //      3. check that we send GPO_INTERACTION message to the correct MB
        msg = mlm_client_recv(gpio_client);
        REQUIRE(msg);
        CHECK(streq(mlm_client_subject(gpio_client), "GPO_INTERACTION"));
        zmsg_print(msg);
        char* zuuid_str = zmsg_popstr(msg);
        char* str       = zmsg_popstr(msg);
        CHECK(streq(str, "gpo-1"));
        zstr_free(&str);
        str = zmsg_popstr(msg);
        CHECK(streq(str, "open"));
        zstr_free(&str);
        zmsg_destroy(&msg);

        //       4. send the reply to unblock the actor
        zmsg_t* reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        mlm_client_sendto(gpio_client, FTY_ALERT_ACTIONS_TEST, "GPO_INTERACTION", NULL, 1000, &reply);

        zstr_free(&zuuid_str);
    }

    // test 10, send asset without contact_email + send an alert on the already known asset
    SECTION("test 10")
    {
        log_debug("test 10");
        //      1. send asset info
        const char* asset_name = "ASSET2";
        zhash_t* aux = zhash_new();
        zhash_insert(aux, "priority", static_cast<void*>(const_cast<char*>("1")));
        zhash_t* ext = zhash_new();
        zhash_insert(ext, "contact_name", static_cast<void*>(const_cast<char*>("eaton Support team")));
        zhash_insert(ext, "name", static_cast<void*>(const_cast<char*>(asset_name)));
        zmsg_t* msg = fty_proto_encode_asset(aux, asset_name, FTY_PROTO_ASSET_OP_UPDATE, ext);
        zhash_destroy(&aux);
        zhash_destroy(&ext);
        REQUIRE(msg);
        mlm_client_send(asset_producer, "Asset message3", &msg);
        zclock_sleep(1000);

        //      2. send alert message
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), ALERT_TTL, "NY_RULE2", asset_name, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        zlist_destroy(&actions);
        REQUIRE(msg);
        std::string atopic2 = "NY_RULE2/CRITICAL@" + std::string(asset_name);
        mlm_client_send(alert_producer, atopic2.c_str(), &msg);
        zclock_sleep(1000);

        //      3. check that we don't generate SENDMAIL_ALERT message as the contact_email is empty
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(email_client), NULL);
        void* which = zpoller_wait(poller, 5000);
        CHECK(which == NULL);
        zpoller_destroy(&poller);
    }

    // test 11: two alerts in quick succession, only one e-mail
    SECTION("test 11")
    {
        log_debug("test 11");
        const char* asset_name = "ASSET3";
        zhash_t*    aux        = zhash_new();
        zhash_insert(aux, "priority", static_cast<void*>(const_cast<char*>("1")));
        zhash_t* ext = zhash_new();
        zhash_insert(ext, "contact_email", static_cast<void*>(const_cast<char*>("eaton Support team")));
        zhash_insert(ext, "name", static_cast<void*>(const_cast<char*>(asset_name)));
        zmsg_t* msg = fty_proto_encode_asset(aux, asset_name, FTY_PROTO_ASSET_OP_UPDATE, ext);
        REQUIRE(msg);
        mlm_client_send(asset_producer, "Asset message3", &msg);
        zclock_sleep(1000);
        zhash_destroy(&aux);
        zhash_destroy(&ext);

        //      1. send an alert on the already known asset
        std::string atopic  = "NY_RULE3/CRITICAL@" + std::string(asset_name);
        zlist_t*    actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), ALERT_TTL, "NY_RULE3", asset_name, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);
        mlm_client_send(alert_producer, atopic.c_str(), &msg);
        zlist_destroy(&actions);

        //      2. read the SENDMAIL_ALERT message
        msg = mlm_client_recv(email_client);
        REQUIRE(msg);
        CHECK(streq(mlm_client_subject(email_client), "SENDMAIL_ALERT"));
        char* zuuid_str = zmsg_popstr(msg);
        zmsg_destroy(&msg);

        //       3. send the reply to unblock the actor
        zmsg_t* reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        REQUIRE(reply);
        mlm_client_sendto(email_client, FTY_ALERT_ACTIONS_TEST, "SENDMAIL_ALERT", NULL, 1000, &reply);

        zstr_free(&zuuid_str);

        //      4. send an alert on the already known asset
        actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), ALERT_TTL, "NY_RULE3", asset_name, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        CHECK(msg);
        mlm_client_send(alert_producer, atopic.c_str(), &msg);
        zlist_destroy(&actions);

        //      5. check that we don't send SENDMAIL_ALERT message (notification interval)
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(email_client), NULL);
        void* which = zpoller_wait(poller, 1000);
        CHECK(which == NULL);
        zpoller_destroy(&poller);
    }

    // test 12, alert without action "EMAIL"
    SECTION("test 12")
    {
        log_debug("test 12");
        const char* asset_name = "ASSET4";
        zhash_t*    aux        = zhash_new();
        zhash_insert(aux, "priority", static_cast<void*>(const_cast<char*>("1")));
        zhash_t* ext = zhash_new();
        zhash_insert(ext, "contact_email", static_cast<void*>(const_cast<char*>("eaton Support team")));
        zhash_insert(ext, "name", static_cast<void*>(const_cast<char*>(asset_name)));
        zmsg_t* msg = fty_proto_encode_asset(aux, asset_name, FTY_PROTO_ASSET_OP_UPDATE, ext);
        REQUIRE(msg);
        mlm_client_send(asset_producer, "Asset message4", &msg);
        zclock_sleep(1000);
        zhash_destroy(&aux);
        zhash_destroy(&ext);

        //      1. send alert message
        std::string atopic  = "NY_RULE4/CRITICAL@" + std::string(asset_name);
        zlist_t*    actions = zlist_new();
        zlist_autofree(actions);
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), ALERT_TTL, "NY_RULE4", asset_name, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);
        mlm_client_send(alert_producer, atopic.c_str(), &msg);
        zlist_destroy(&actions);

        //      2. we don't send SENDMAIL_ALERT message
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(email_client), NULL);
        void* which = zpoller_wait(poller, 1000);
        CHECK(which == NULL);
        zpoller_destroy(&poller);
    }

    // test 13
    SECTION("test 13")
    {
        log_debug("test 13");
        const char* asset_name6  = "asset_6";
        const char* rule_name6   = "rule_name_6";
        std::string alert_topic6 = std::string(rule_name6) + "/CRITICAL@" + std::string(asset_name6);

        //      1. send asset info without contact_email
        zhash_t* aux = zhash_new();
        REQUIRE(aux);
        zhash_insert(aux, "priority", static_cast<void*>(const_cast<char*>("1")));
        zhash_t* ext = zhash_new();
        REQUIRE(ext);
        zhash_insert(ext, "name", static_cast<void*>(const_cast<char*>(asset_name6)));
        zmsg_t* msg = fty_proto_encode_asset(aux, asset_name6, FTY_PROTO_ASSET_OP_UPDATE, ext);
        REQUIRE(msg);
        int rv = mlm_client_send(asset_producer, "Asset message6", &msg);
        REQUIRE(rv != -1);
        // Ensure, that malamute will deliver ASSET message before ALERT message
        zclock_sleep(1000);

        //      2. send alert message
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), ALERT_TTL, rule_name6, asset_name6, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        zlist_destroy(&actions);
        REQUIRE(msg);
        rv = mlm_client_send(alert_producer, alert_topic6.c_str(), &msg);
        REQUIRE(rv != -1);

        //      3. check that we don't generate SENDMAIL_ALERT message as the contact_email is empty
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(email_client), NULL);
        void* which = zpoller_wait(poller, 5000);
        CHECK(which == NULL);
        zpoller_destroy(&poller);

        //      4. send asset info one more time, but with contact_email
        zhash_insert(ext, "contact_email", static_cast<void*>(const_cast<char*>("scenario6.email@eaton.com")));
        msg = fty_proto_encode_asset(aux, asset_name6, "update", ext);
        zhash_destroy(&aux);
        zhash_destroy(&ext);
        REQUIRE(msg);
        rv = mlm_client_send(asset_producer, "Asset message6", &msg);
        REQUIRE(rv != -1);
        // Ensure, that malamute will deliver ASSET message before ALERT message
        zclock_sleep(1000);

        //      5. send alert message again
        actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), ALERT_TTL, rule_name6, asset_name6, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);
        rv = mlm_client_send(alert_producer, alert_topic6.c_str(), &msg);
        REQUIRE(rv != -1);
        zlist_destroy(&actions);

        //      6. Email SHOULD be generated
        poller = zpoller_new(mlm_client_msgpipe(email_client), NULL);
        which = zpoller_wait(poller, 5000);
        CHECK(which != NULL);
        zpoller_destroy(&poller);
        msg = mlm_client_recv(email_client);
        REQUIRE(msg);
        CHECK(streq(mlm_client_subject(email_client), "SENDMAIL_ALERT"));
        char* zuuid_str = zmsg_popstr(msg);
        zmsg_destroy(&msg);

        //       7. send the reply to unblock the actor
        zmsg_t* reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        mlm_client_sendto(email_client, FTY_ALERT_ACTIONS_TEST, "SENDMAIL_ALERT", NULL, 1000, &reply);

        zstr_free(&zuuid_str);
    }

    // test 14, on ACK-SILENCE we send only one e-mail and then stop
    SECTION("test 14")
    {
        log_debug("test 14");
        //      1. send an alert on the already known asset
        const char* asset_name = "ASSET7";
        //      1. send asset info without email
        zhash_t* aux = zhash_new();
        REQUIRE(aux);
        zhash_insert(aux, "priority", static_cast<void*>(const_cast<char*>("1")));
        zhash_t* ext = zhash_new();
        REQUIRE(ext);
        zhash_insert(ext, "name", static_cast<void*>(const_cast<char*>(asset_name)));
        zhash_insert(ext, "contact_email", static_cast<void*>(const_cast<char*>("scenario7.email@eaton.com")));
        zmsg_t* msg = fty_proto_encode_asset(aux, asset_name, FTY_PROTO_ASSET_OP_UPDATE, ext);
        zhash_destroy(&aux);
        zhash_destroy(&ext);
        REQUIRE(msg);
        int rv = mlm_client_send(asset_producer, "Asset message6", &msg);
        REQUIRE(rv != -1);
        // Ensure, that malamute will deliver ASSET message before ALERT message
        zclock_sleep(1000);

        std::string atopic  = "Scenario7/CRITICAL@" + std::string(asset_name);
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), ALERT_TTL, "Scenario7", asset_name, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        zlist_destroy(&actions);
        REQUIRE(msg);
        mlm_client_send(alert_producer, atopic.c_str(), &msg);

        //      2. read the email generated for alert
        msg = mlm_client_recv(email_client);
        REQUIRE(msg);
        CHECK(streq(mlm_client_subject(email_client), "SENDMAIL_ALERT"));
        char* zuuid_str = zmsg_popstr(msg);
        zmsg_destroy(&msg);

        //       3. send the reply to unblock the actor
        zmsg_t* reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        mlm_client_sendto(email_client, FTY_ALERT_ACTIONS_TEST, "SENDMAIL_ALERT", NULL, 1000, &reply);

        zstr_free(&zuuid_str);

        //      4. send an alert on the already known asset
        actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), ALERT_TTL, "Scenario7", asset_name,
            "ACK-SILENCE", "CRITICAL", "ASDFKLHJH", actions);
        CHECK(msg);
        mlm_client_send(alert_producer, atopic.c_str(), &msg);
        zlist_destroy(&actions);

        //      5. read the email generated for alert
        msg = mlm_client_recv(email_client);
        REQUIRE(msg);
        CHECK(streq(mlm_client_subject(email_client), "SENDMAIL_ALERT"));
        zuuid_str = zmsg_popstr(msg);
        zmsg_destroy(&msg);

        //       6. send the reply to unblock the actor
        reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        mlm_client_sendto(email_client, FTY_ALERT_ACTIONS_TEST, "SENDMAIL_ALERT", NULL, 1000, &reply);

        zstr_free(&zuuid_str);

        // wait for msg processing
        log_debug("sleeping for 20 seconds...");
        zclock_sleep(20 * 1000);

        //      7. send an alert again
        actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), ALERT_TTL, "Scenario7", asset_name,
            "ACK-SILENCE", "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);
        mlm_client_send(alert_producer, atopic.c_str(), &msg);
        zlist_destroy(&actions);

        //      8. email should not be sent (it is in the state, where alerts are not being sent)
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(email_client), NULL);
        void* which = zpoller_wait(poller, 2000);
        CHECK(which == NULL);
        zpoller_destroy(&poller);
    }

    // test 15 ===============================================
    //
    //------------------------------------------------------------------------------------------------------------------------------------->
    // t
    //
    //  asset is known       alert comes    no email        asset_info        alert comes   email send    alert comes
    //  (<5min)   email NOT send
    // (without email)                                   updated with email
    SECTION("test 15")
    {
        log_debug("test 15");
        const char* asset_name8  = "ROZ.UPS36";
        const char* rule_name8   = "rule_name_8";
        std::string alert_topic8 = std::string(rule_name8) + "/CRITICAL@" + std::string(asset_name8);

        //      1. send asset info without email/sms contact
        zhash_t* aux = zhash_new();
        REQUIRE(aux);
        zhash_insert(aux, "priority", static_cast<void*>(const_cast<char*>("1")));
        zhash_t* ext = zhash_new();
        REQUIRE(ext);
        zhash_insert(ext, "name", static_cast<void*>(const_cast<char*>(asset_name8)));
        zmsg_t* msg = fty_proto_encode_asset(aux, asset_name8, FTY_PROTO_ASSET_OP_UPDATE, ext);
        REQUIRE(msg);
        int rv = mlm_client_send(asset_producer, "Asset message8", &msg);
        REQUIRE(rv != -1);
        zclock_sleep(1000);

        //      2. send alert message
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        zlist_append(actions, static_cast<void*>(const_cast<char*>("SMS")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), ALERT_TTL, rule_name8, asset_name8, "ACTIVE",
            "WARNING", "Default load in ups ROZ.UPS36 is high", actions);
        zlist_destroy(&actions);
        REQUIRE(msg);
        rv = mlm_client_send(alert_producer, alert_topic8.c_str(), &msg);
        REQUIRE(rv != -1);
        zclock_sleep(1000);

        //      3. check that we don't generate SENDMAIL_ALERT/SENDSMS_ALERT message as the email/sms contact are empty
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(email_client), NULL);
        CHECK(poller);
        void* which = zpoller_wait(poller, 5000);
        CHECK(which == NULL);
        zpoller_destroy(&poller);

        //      4. send asset info one more time, but with email/sms contact
        zhash_insert(ext, "contact_email", static_cast<void*>(const_cast<char*>("scenario8.email@eaton.com")));
        zhash_insert(ext, "contact_sms", static_cast<void*>(const_cast<char*>("scenario8.sms@eaton.com")));
        msg = fty_proto_encode_asset(aux, asset_name8, "update", ext);
        zhash_destroy(&aux);
        zhash_destroy(&ext);
        REQUIRE(msg);
        rv = mlm_client_send(asset_producer, "Asset message8", &msg);
        REQUIRE(rv != -1);
        zclock_sleep(1000);

        //      5. send alert message again second
        actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        zlist_append(actions, static_cast<void*>(const_cast<char*>("SMS")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), ALERT_TTL, rule_name8, asset_name8, "ACTIVE",
            "WARNING", "Default load in ups ROZ.UPS36 is high", actions);
        zlist_destroy(&actions);
        REQUIRE(msg);
        rv = mlm_client_send(alert_producer, alert_topic8.c_str(), &msg);
        REQUIRE(rv != -1);
        zclock_sleep(1000);

        //      6. Email SHOULD be generated (first)
        poller = zpoller_new(mlm_client_msgpipe(email_client), NULL);
        CHECK(poller);
        which = zpoller_wait(poller, 5000);
        CHECK(which != NULL);
        zpoller_destroy(&poller);
        msg = mlm_client_recv(email_client);
        REQUIRE(msg);
        CHECK(streq(mlm_client_subject(email_client), "SENDMAIL_ALERT"));
        char* zuuid_str = zmsg_popstr(msg);
        zmsg_destroy(&msg);

        //       7. send the reply to unblock the actor
        zmsg_t* reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        mlm_client_sendto(email_client, FTY_ALERT_ACTIONS_TEST, "SENDMAIL_ALERT", NULL, 1000, &reply);

        zstr_free(&zuuid_str);

        //       8. SMS SHOULD be generated
        poller = zpoller_new(mlm_client_msgpipe(email_client), NULL);
        CHECK(poller);
        which = zpoller_wait(poller, 5000);
        CHECK(which != NULL);
        zpoller_destroy(&poller);
        msg = mlm_client_recv(email_client);
        REQUIRE(msg);
        CHECK(streq(mlm_client_subject(email_client), "SENDSMS_ALERT"));
        zuuid_str = zmsg_popstr(msg);
        zmsg_destroy(&msg);

        //       9. send the reply to unblock the actor
        reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        mlm_client_sendto(email_client, FTY_ALERT_ACTIONS_TEST, "SENDSMS_ALERT", NULL, 1000, &reply);

        zstr_free(&zuuid_str);

        //       10. send alert message again third time
        actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        zlist_append(actions, static_cast<void*>(const_cast<char*>("SMS")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), ALERT_TTL, rule_name8, asset_name8, "ACTIVE",
            "WARNING", "Default load in ups ROZ.UPS36 is high", actions);
        zlist_destroy(&actions);
        REQUIRE(msg);
        rv = mlm_client_send(alert_producer, alert_topic8.c_str(), &msg);
        REQUIRE(rv != -1);
        zclock_sleep(1000);

        //       11. Email SHOULD NOT be generated
        poller = zpoller_new(mlm_client_msgpipe(email_client), NULL);
        CHECK(poller);
        which = zpoller_wait(poller, 5000);
        CHECK(which == NULL);
        zpoller_destroy(&poller);
    }

    mlm_client_destroy(&gpio_client);
    mlm_client_destroy(&email_client);
    mlm_client_destroy(&alert_producer);
    mlm_client_destroy(&asset_producer);
    zactor_destroy(&alert_actions);
    zactor_destroy(&server);
}
