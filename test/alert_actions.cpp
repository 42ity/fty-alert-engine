#include "src/fty_alert_actions.h"
#include <catch2/catch.hpp>
#include <fty_log.h>

#define TEST_ASSETS "ASSETS-TEST"
#define TEST_ALERTS "ALERTS-TEST"

#define FTY_EMAIL_AGENT_ADDRESS_TEST       "fty-email-test"
#define FTY_SENSOR_GPIO_AGENT_ADDRESS_TEST "fty-sensor-gpio-test"

#define TEST_VARS                                                                                                      \
    zlist_t*    testing_var_recv    = NULL;                                                                            \
    int         testing_var_send    = 0;                                                                               \
    const char* testing_var_uuid    = NULL;                                                                            \
    const char* testing_var_subject = NULL;
#define TEST_FUNCTIONS                                                                                                 \
    int testing_fun_sendto(long int line, const char* func, mlm_client_t* client, const char* address,                 \
        const char* subject, void* tracker, uint32_t /* timeout */, zmsg_t** msg)                                      \
    {                                                                                                                  \
        REQUIRE(client);                /* prevent not-used warning */                                                 \
        REQUIRE((tracker || !tracker)); /* prevent not-used warning */                                                 \
        /* CHECK(timeout >= 0); */      /* prevent not-used warning */                                                 \
        log_debug("%s: called testing sendto on line %ld, function %s for client %s with subject %s", __FILE__, line,  \
            func, address, subject);                                                                                   \
        zmsg_destroy(msg);                                                                                             \
        return testing_var_send;                                                                                       \
    }                                                                                                                  \
    int testing_fun_sendtox(                                                                                           \
        long int line, const char* func, mlm_client_t* client, const char* address, const char* subject, ...)          \
    {                                                                                                                  \
        REQUIRE(client);                                                                                               \
        log_debug("%s: called testing sendtox on line %ld, function %s for client %s with subject %s", __FILE__, line, \
            func, address, subject);                                                                                   \
        return testing_var_send;                                                                                       \
    }                                                                                                                  \
    zmsg_t* testing_fun_recv(long int line, const char* func, mlm_client_t* client)                                    \
    {                                                                                                                  \
        REQUIRE(client);                                                                                               \
        log_debug("%s: called testing recv on line %ld, function %s", __FILE__, line, func);                           \
        return static_cast<zmsg_t*>(zlist_pop(testing_var_recv));                                                      \
    }                                                                                                                  \
    void* testing_fun_wait(long int line, const char* func)                                                            \
    {                                                                                                                  \
        log_debug("%s: called testing wait on line %ld, function %s", __FILE__, line, func);                           \
        return (0 == zlist_size(testing_var_recv) ? NULL : reinterpret_cast<void*>(1));                                \
    }
#ifdef __GNUC__
#define unlikely(x) __builtin_expect(0 != x, 0)
#else
#define unlikely(x) (0 != x)
#endif
#define zpoller_wait(...)  (unlikely(testing) ? (testing_fun_wait(__LINE__, __FUNCTION__)) : (zpoller_wait(__VA_ARGS__)))
#define mlm_client_recv(a) (unlikely(testing) ? (testing_fun_recv(__LINE__, __FUNCTION__, a)) : (mlm_client_recv(a)))
#define mlm_client_sendtox(a, b, c, ...)                                                                               \
    (unlikely(testing) ? (testing_fun_sendtox(__LINE__, __FUNCTION__, a, b, c, __VA_ARGS__))                           \
                       : (mlm_client_sendtox(a, b, c, __VA_ARGS__)))
#define mlm_client_sendto(a, b, c, d, e, f)                                                                            \
    (unlikely(testing) ? (testing_fun_sendto(__LINE__, __FUNCTION__, a, b, c, d, e, f))                                \
                       : (mlm_client_sendto(a, b, c, d, e, f)))
#define zuuid_str_canonical(...) (unlikely(testing) ? (testing_var_uuid) : (zuuid_str_canonical(__VA_ARGS__)))
#define mlm_client_subject(...)  (unlikely(testing) ? (testing_var_subject) : (mlm_client_subject(__VA_ARGS__)))
#define CLEAN_RECV                                                                                                     \
    {                                                                                                                  \
        zmsg_t* l = static_cast<zmsg_t*>(zlist_first(testing_var_recv));                                               \
        int     c = 0;                                                                                                 \
        while (NULL != l) {                                                                                            \
            ++c;                                                                                                       \
            zmsg_destroy(&l);                                                                                          \
            l = static_cast<zmsg_t*>(zlist_next(testing_var_recv));                                                    \
        }                                                                                                              \
        if (0 != c)                                                                                                    \
            log_debug(                                                                                                 \
                "%s: while performing CLEAN_RECV, %d messages were found in prepared list "                            \
                "the list was not clean in the end",                                                                   \
                __FILE__);                                                                                             \
        zlist_destroy(&testing_var_recv);                                                                              \
    }
#define INIT_RECV                                                                                                      \
    {                                                                                                                  \
        testing_var_recv = zlist_new();                                                                                \
    }
#define MSG_TO_RECV(x)                                                                                                 \
    {                                                                                                                  \
        zlist_append(testing_var_recv, x);                                                                             \
    }
#define SET_SEND(x)                                                                                                    \
    {                                                                                                                  \
        testing_var_send = x;                                                                                          \
    }
#define SET_UUID(x)                                                                                                    \
    {                                                                                                                  \
        testing_var_uuid = x;                                                                                          \
    }
#define GET_UUID testing_var_uuid
#define SET_SUBJECT(x)                                                                                                 \
    {                                                                                                                  \
        testing_var_subject = x;                                                                                       \
    }
int testing = 0;
TEST_VARS
TEST_FUNCTIONS

TEST_CASE("alert actions test", "[.]")
{
    setenv("BIOS_LOG_PATTERN", "%D %c [%t] -%-5p- %M (%l) %m%n", 1);
    ManageFtyLog::setInstanceFtylog("fty-alert-actions");

    testing = 1;
    SET_SUBJECT("testing");

    // test 1, simple create/destroy self test
    {
        log_debug("test 1");
        fty_alert_actions_t* self = fty_alert_actions_new();
        REQUIRE(self);
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

    // test 3, simple create/destroy cache item test without need to send ASSET_DETAILS
    {
        log_debug("test 3");
        fty_alert_actions_t* self = fty_alert_actions_new();
        REQUIRE(self);
        fty_proto_t* asset = fty_proto_new(FTY_PROTO_ASSET);
        REQUIRE(asset);
        zhash_insert(self->assets_cache, "myasset-3", asset);
        fty_proto_t* msg = fty_proto_new(FTY_PROTO_ALERT);
        REQUIRE(msg);
        fty_proto_set_name(msg, "myasset-3");

        s_alert_cache* cache = new_alert_cache_item(self, msg);
        CHECK(cache);
        delete_alert_cache_item(cache);

        fty_proto_destroy(&asset);
        fty_alert_actions_destroy(&self);
    }

    // test 4, simple create/destroy cache item test with need to send ASSET_DETAILS
    {
        log_debug("test 4");
        SET_UUID("uuid-test");
        zhash_t* aux      = zhash_new();
        zhash_t* ext      = zhash_new();
        zmsg_t*  resp_msg = fty_proto_encode_asset(aux, "myasset-2", FTY_PROTO_ASSET_OP_UPDATE, ext);
        zmsg_pushstr(resp_msg, GET_UUID);
        REQUIRE(resp_msg);
        INIT_RECV;
        MSG_TO_RECV(resp_msg);
        SET_SEND(0);
        fty_alert_actions_t* self = fty_alert_actions_new();
        REQUIRE(self);
        fty_proto_t* msg = fty_proto_new(FTY_PROTO_ALERT);
        CHECK(msg);
        fty_proto_set_name(msg, "myasset-4");

        s_alert_cache* cache = new_alert_cache_item(self, msg);
        REQUIRE(cache);
        delete_alert_cache_item(cache);

        fty_alert_actions_destroy(&self);
        zhash_destroy(&aux);
        zhash_destroy(&ext);
        CLEAN_RECV;
    }

    // test 5, processing of alerts from stream
    {
        log_debug("test 5");
        SET_UUID("uuid-test");
        zhash_t* aux      = zhash_new();
        zhash_t* ext      = zhash_new();
        zmsg_t*  resp_msg = fty_proto_encode_asset(aux, "SOME_ASSET", FTY_PROTO_ASSET_OP_UPDATE, ext);
        zmsg_pushstr(resp_msg, GET_UUID);
        REQUIRE(resp_msg);
        INIT_RECV;
        MSG_TO_RECV(resp_msg);
        SET_SEND(0);

        fty_alert_actions_t* self = fty_alert_actions_new();
        REQUIRE(self);

        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("SMS")));
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        zmsg_t* msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, "SOME_RULE", "SOME_ASSET",
            "ACTIVE", "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);

        // send an active alert
        s_handle_stream_deliver(self, &msg, "");
        zlist_destroy(&actions);
        zclock_sleep(1000);

        // check the alert cache
        CHECK(zhash_size(self->alerts_cache) == 1);
        s_alert_cache* cached = static_cast<s_alert_cache*>(zhash_first(self->alerts_cache));
        fty_proto_t*   alert  = cached->alert_msg;
        CHECK(streq(fty_proto_rule(alert), "SOME_RULE"));
        CHECK(streq(fty_proto_name(alert), "SOME_ASSET"));
        CHECK(streq(fty_proto_state(alert), "ACTIVE"));
        CHECK(streq(fty_proto_severity(alert), "CRITICAL"));
        CHECK(streq(fty_proto_description(alert), "ASDFKLHJH"));
        CHECK(streq(fty_proto_action_first(alert), "SMS"));
        CHECK(streq(fty_proto_action_next(alert), "EMAIL"));

        // resolve the alert
        actions = zlist_new();
        zlist_autofree(actions);
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, "SOME_RULE", "SOME_ASSET",
            "RESOLVED", "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);

        s_handle_stream_deliver(self, &msg, "");
        zlist_destroy(&actions);
        zclock_sleep(1000);

        // alert cache is now empty
        CHECK(zhash_size(self->alerts_cache) == 0);
        // clean up after
        fty_alert_actions_destroy(&self);
        zhash_destroy(&aux);
        zhash_destroy(&ext);
        CLEAN_RECV;
    }
    // test 6, processing of assets from stream
    {
        log_debug("test 6");
        fty_alert_actions_t* self = fty_alert_actions_new();
        REQUIRE(self);

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
    {
        // test 7, send asset + send an alert on the already known correct asset
        // + delete the asset + check that alert disappeared

        log_debug("test 7");
        SET_UUID("uuid-test");
        zmsg_t* resp_msg = zmsg_new();
        zmsg_addstr(resp_msg, GET_UUID);
        zmsg_addstr(resp_msg, "OK");
        REQUIRE(resp_msg);
        INIT_RECV;
        MSG_TO_RECV(resp_msg);
        SET_SEND(0);

        fty_alert_actions_t* self = fty_alert_actions_new();
        CHECK(self);
        //      1. send asset info
        const char* asset_name = "ASSET1";
        zhash_t*    aux        = zhash_new();
        zhash_insert(aux, "priority", static_cast<void*>(const_cast<char*>("1")));
        zhash_t* ext = zhash_new();
        zhash_insert(ext, "contact_email", static_cast<void*>(const_cast<char*>("scenario1.email@eaton.com")));
        zhash_insert(ext, "contact_name", static_cast<void*>(const_cast<char*>("eaton Support team")));
        zhash_insert(ext, "name", static_cast<void*>(const_cast<char*>(asset_name)));
        zmsg_t* msg = fty_proto_encode_asset(aux, asset_name, FTY_PROTO_ASSET_OP_UPDATE, ext);
        REQUIRE(msg);
        s_handle_stream_deliver(self, &msg, "Asset message1");
        // CHECK (zhash_size (self->assets_cache) != 0);
        zhash_destroy(&aux);
        zhash_destroy(&ext);
        zclock_sleep(1000);

        //      2. send alert message
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, "NY_RULE", asset_name, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);
        std::string atopic = "NY_RULE/CRITICAL@" + std::string(asset_name);
        s_handle_stream_deliver(self, &msg, atopic.c_str());
        zclock_sleep(1000);
        // CHECK ( zhash_size (self->assets_cache) != 0 );
        zlist_destroy(&actions);

        //      3. delete the asset
        msg = fty_proto_encode_asset(NULL, asset_name, FTY_PROTO_ASSET_OP_DELETE, NULL);
        REQUIRE(msg);

        // CHECK ( zhash_size (self->assets_cache) != 0 );
        s_handle_stream_deliver(self, &msg, "Asset message 1");
        zclock_sleep(1000);

        //      4. check that alert disappeared
        CHECK(zhash_size(self->alerts_cache) == 0);
        fty_alert_actions_destroy(&self);
        CLEAN_RECV;
    }
    // do the rest of the tests the ugly way, since it's the least complicated option
    testing = 0;

    const char* TEST_ENDPOINT          = "inproc://fty-alert-actions-test";
    const char* FTY_ALERT_ACTIONS_TEST = "fty-alert-actions-test";

    zactor_t* server = zactor_new(mlm_server, static_cast<void*>(const_cast<char*>("Malamute_alert_actions_test")));
    CHECK(server != NULL);
    zstr_sendx(server, "BIND", TEST_ENDPOINT, NULL);

    zactor_t* alert_actions =
        zactor_new(fty_alert_actions, static_cast<void*>(const_cast<char*>(FTY_ALERT_ACTIONS_TEST)));
    zstr_sendx(alert_actions, "CONNECT", TEST_ENDPOINT, NULL);
    zstr_sendx(alert_actions, "CONSUMER", TEST_ASSETS, ".*", NULL);
    zstr_sendx(alert_actions, "CONSUMER", TEST_ALERTS, ".*", NULL);

    mlm_client_t* asset_producer = mlm_client_new();
    mlm_client_connect(asset_producer, TEST_ENDPOINT, 1000, "asset-producer-test");
    mlm_client_set_producer(asset_producer, TEST_ASSETS);

    mlm_client_t* alert_producer = mlm_client_new();
    mlm_client_connect(alert_producer, TEST_ENDPOINT, 1000, "alert-producer-test");
    mlm_client_set_producer(alert_producer, TEST_ASSETS);

    mlm_client_t* email_client = mlm_client_new();
    mlm_client_connect(email_client, TEST_ENDPOINT, 1000, FTY_EMAIL_AGENT_ADDRESS_TEST);

    // test 8, send asset with e-mail + send an alert on the already known correct asset (with e-mail action)
    // + check that we send SENDMAIL_ALERT message
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
        REQUIRE(msg);
        mlm_client_send(asset_producer, "Asset message1", &msg);
        zclock_sleep(1000);
        zhash_destroy(&aux);
        zhash_destroy(&ext);

        //      2. send alert message
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, "NY_RULE", asset_name, "ACTIVE",
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
    mlm_client_t* gpio_client = mlm_client_new();
    mlm_client_connect(gpio_client, TEST_ENDPOINT, 1000, FTY_SENSOR_GPIO_AGENT_ADDRESS_TEST);

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
        REQUIRE(msg);
        mlm_client_send(asset_producer, "Asset message1", &msg);
        zclock_sleep(1000);
        zhash_destroy(&aux);
        zhash_destroy(&ext);

        //      2. send alert message
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("GPO_INTERACTION:gpo-1:open")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, "NY_RULE1", asset_name1, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);
        std::string atopic = "NY_RULE1/CRITICAL@" + std::string(asset_name1);
        mlm_client_send(alert_producer, atopic.c_str(), &msg);
        zlist_destroy(&actions);

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

    mlm_client_destroy(&gpio_client);
    // skip the test for alert on unknown asset since agent behaves differently now

    // test 10, send asset without email + send an alert on the already known asset
    {
        log_debug("test 10");
        //      1. send asset info
        const char* asset_name = "ASSET2";
        zhash_t*    aux        = zhash_new();
        zhash_insert(aux, "priority", static_cast<void*>(const_cast<char*>("1")));
        zhash_t* ext = zhash_new();
        zhash_insert(ext, "contact_name", static_cast<void*>(const_cast<char*>("eaton Support team")));
        zhash_insert(ext, "name", static_cast<void*>(const_cast<char*>(asset_name)));
        zmsg_t* msg = fty_proto_encode_asset(aux, asset_name, FTY_PROTO_ASSET_OP_UPDATE, ext);
        REQUIRE(msg);
        mlm_client_send(asset_producer, "Asset message3", &msg);
        zclock_sleep(1000);
        zhash_destroy(&aux);
        zhash_destroy(&ext);

        //      2. send alert message
        zlist_t* actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, "NY_RULE2", asset_name, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);
        std::string atopic2 = "NY_RULE2/CRITICAL@" + std::string(asset_name);
        mlm_client_send(alert_producer, atopic2.c_str(), &msg);
        zlist_destroy(&actions);

        //      3. check that we generate SENDMAIL_ALERT message with empty contact
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
        CHECK(streq(str, ""));
        zstr_free(&str);
        zmsg_destroy(&msg);

        //       4. send the reply to unblock the actor
        zmsg_t* reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        zclock_sleep(1000);
        mlm_client_sendto(email_client, FTY_ALERT_ACTIONS_TEST, "SENDMAIL_ALERT", NULL, 1000, &reply);

        zstr_free(&zuuid_str);
    }
    zclock_sleep(1000);
    // test 11: two alerts in quick succession, only one e-mail
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
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, "NY_RULE3", asset_name, "ACTIVE",
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
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, "NY_RULE3", asset_name, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        CHECK(msg);
        mlm_client_send(alert_producer, atopic.c_str(), &msg);
        zlist_destroy(&actions);

        //      5. check that we don't send SENDMAIL_ALERT message (notification interval)
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(email_client), NULL);
        void*      which  = zpoller_wait(poller, 1000);
        CHECK(which == NULL);
        zpoller_destroy(&poller);
    }
    // test 12, alert without action "EMAIL"
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
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, "NY_RULE4", asset_name, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);
        mlm_client_send(alert_producer, atopic.c_str(), &msg);
        zlist_destroy(&actions);

        //      2. we don't send SENDMAIL_ALERT message
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(email_client), NULL);
        void*      which  = zpoller_wait(poller, 1000);
        CHECK(which == NULL);
        zpoller_destroy(&poller);
    }
    // test13  ===============================================
    //
    //------------------------------------------------------------------------------------------------> t
    //
    //  asset is known       alert comes    no email        asset_info        alert comes   email send
    // (without email)                                   updated with email
    {
        log_debug("test 13");
        const char* asset_name6  = "asset_6";
        const char* rule_name6   = "rule_name_6";
        std::string alert_topic6 = std::string(rule_name6) + "/CRITICAL@" + std::string(asset_name6);

        //      1. send asset info without email
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
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, rule_name6, asset_name6, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);
        rv = mlm_client_send(alert_producer, alert_topic6.c_str(), &msg);
        REQUIRE(rv != -1);
        zlist_destroy(&actions);

        //      3. check that we generate SENDMAIL_ALERT message with empty contact
        zmsg_t* email = mlm_client_recv(email_client);
        REQUIRE(email);
        CHECK(streq(mlm_client_subject(email_client), "SENDMAIL_ALERT"));
        char* zuuid_str = zmsg_popstr(email);
        char* str       = zmsg_popstr(email);
        CHECK(streq(str, "1"));
        zstr_free(&str);
        str = zmsg_popstr(email);
        CHECK(streq(str, asset_name6));
        zstr_free(&str);
        str = zmsg_popstr(email);
        CHECK(streq(str, ""));
        zstr_free(&str);
        zmsg_destroy(&email);

        //       4. send the reply to unblock the actor
        zmsg_t* reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        mlm_client_sendto(email_client, FTY_ALERT_ACTIONS_TEST, "SENDMAIL_ALERT", NULL, 1000, &reply);

        zstr_free(&zuuid_str);

        //      5. send asset info one more time, but with email
        zhash_insert(ext, "contact_email", static_cast<void*>(const_cast<char*>("scenario6.email@eaton.com")));
        msg = fty_proto_encode_asset(aux, asset_name6, "update", ext);
        REQUIRE(msg);
        rv = mlm_client_send(asset_producer, "Asset message6", &msg);
        REQUIRE(rv != -1);
        // Ensure, that malamute will deliver ASSET message before ALERT message
        zhash_destroy(&aux);
        zhash_destroy(&ext);
        zclock_sleep(1000);

        //      5. send alert message again
        actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, rule_name6, asset_name6, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);
        rv = mlm_client_send(alert_producer, alert_topic6.c_str(), &msg);
        REQUIRE(rv != -1);
        zlist_destroy(&actions);

        //      6. Email SHOULD be generated
        msg = mlm_client_recv(email_client);
        REQUIRE(msg);
        CHECK(streq(mlm_client_subject(email_client), "SENDMAIL_ALERT"));
        zuuid_str = zmsg_popstr(msg);
        zmsg_destroy(&msg);

        //       7. send the reply to unblock the actor
        reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        mlm_client_sendto(email_client, FTY_ALERT_ACTIONS_TEST, "SENDMAIL_ALERT", NULL, 1000, &reply);

        zstr_free(&zuuid_str);
    }
    // test 14, on ACK-SILENCE we send only one e-mail and then stop
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
        zmsg_t* msg = fty_proto_encode_asset(aux, asset_name, FTY_PROTO_ASSET_OP_UPDATE, ext);
        REQUIRE(msg);
        int rv = mlm_client_send(asset_producer, "Asset message6", &msg);
        REQUIRE(rv != -1);
        // Ensure, that malamute will deliver ASSET message before ALERT message
        zclock_sleep(1000);
        zhash_destroy(&aux);
        zhash_destroy(&ext);

        std::string atopic  = "Scenario7/CRITICAL@" + std::string(asset_name);
        zlist_t*    actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, "Scenario7", asset_name, "ACTIVE",
            "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);
        mlm_client_send(alert_producer, atopic.c_str(), &msg);
        zlist_destroy(&actions);

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
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, "Scenario7", asset_name,
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

        // wait for 5 minutes
        zstr_sendx(alert_actions, "TESTTIMEOUT", "1000", NULL);
        zstr_sendx(alert_actions, "TESTCHECKINTERVAL", "20000", NULL);
        log_debug("sleeping for 20 seconds...");
        zclock_sleep(20 * 1000);
        //      7. send an alert again
        actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, "Scenario7", asset_name,
            "ACK-SILENCE", "CRITICAL", "ASDFKLHJH", actions);
        REQUIRE(msg);
        mlm_client_send(alert_producer, atopic.c_str(), &msg);
        zlist_destroy(&actions);

        //      8. email should not be sent (it is in the state, where alerts are not being sent)
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(email_client), NULL);
        void*      which  = zpoller_wait(poller, 1000);
        CHECK(which == NULL);
        zpoller_destroy(&poller);
        zclock_sleep(1500);
    }
    // test 15 ===============================================
    //
    //------------------------------------------------------------------------------------------------------------------------------------->
    // t
    //
    //  asset is known       alert comes    no email        asset_info        alert comes   email send    alert comes
    //  (<5min)   email NOT send
    // (without email)                                   updated with email
    {
        log_debug("test 15");
        const char* asset_name8  = "ROZ.UPS36";
        const char* rule_name8   = "rule_name_8";
        std::string alert_topic8 = std::string(rule_name8) + "/CRITICAL@" + std::string(asset_name8);

        //      1. send asset info without email
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
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, rule_name8, asset_name8, "ACTIVE",
            "WARNING", "Default load in ups ROZ.UPS36 is high", actions);
        REQUIRE(msg);
        rv = mlm_client_send(alert_producer, alert_topic8.c_str(), &msg);
        REQUIRE(rv != -1);
        zlist_destroy(&actions);

        //      3. check that we generate SENDMAIL_ALERT message with empty contact
        zmsg_t* email = mlm_client_recv(email_client);
        REQUIRE(email);
        CHECK(streq(mlm_client_subject(email_client), "SENDMAIL_ALERT"));
        char* zuuid_str = zmsg_popstr(email);
        char* str       = zmsg_popstr(email);
        CHECK(streq(str, "1"));
        zstr_free(&str);
        str = zmsg_popstr(email);
        CHECK(streq(str, asset_name8));
        zstr_free(&str);
        str = zmsg_popstr(email);
        CHECK(streq(str, ""));
        zstr_free(&str);
        zmsg_destroy(&email);

        //       4. send the reply to unblock the actor
        zmsg_t* reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        zclock_sleep(1000);
        mlm_client_sendto(email_client, FTY_ALERT_ACTIONS_TEST, "SENDMAIL_ALERT", NULL, 1000, &reply);

        zstr_free(&zuuid_str);
        zclock_sleep(1000);

        //      3. check that we generate SENDSMS_ALERT message with empty contact
        email = mlm_client_recv(email_client);
        REQUIRE(email);
        log_debug(mlm_client_subject(email_client));
        CHECK(streq(mlm_client_subject(email_client), "SENDSMS_ALERT"));
        zuuid_str = zmsg_popstr(email);
        str       = zmsg_popstr(email);
        CHECK(streq(str, "1"));
        zstr_free(&str);
        str = zmsg_popstr(email);
        CHECK(streq(str, asset_name8));
        zstr_free(&str);
        str = zmsg_popstr(email);
        CHECK(streq(str, ""));
        zstr_free(&str);
        zmsg_destroy(&email);

        //       4. send the reply to unblock the actor
        reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        mlm_client_sendto(email_client, FTY_ALERT_ACTIONS_TEST, "SENDMAIL_ALERT", NULL, 1000, &reply);

        zstr_free(&zuuid_str);

        //      5. send asset info one more time, but with email
        zhash_insert(ext, "contact_email", static_cast<void*>(const_cast<char*>("scenario8.email@eaton.com")));
        msg = fty_proto_encode_asset(aux, asset_name8, "update", ext);
        REQUIRE(msg);
        rv = mlm_client_send(asset_producer, "Asset message8", &msg);
        REQUIRE(rv != -1);

        zhash_destroy(&aux);
        zhash_destroy(&ext);
        zclock_sleep(1000);

        //      6. send alert message again second
        actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        zlist_append(actions, static_cast<void*>(const_cast<char*>("SMS")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, rule_name8, asset_name8, "ACTIVE",
            "WARNING", "Default load in ups ROZ.UPS36 is high", actions);
        REQUIRE(msg);
        rv = mlm_client_send(alert_producer, alert_topic8.c_str(), &msg);
        REQUIRE(rv != -1);
        zlist_destroy(&actions);

        //      6. Email SHOULD be generated
        msg = mlm_client_recv(email_client);
        REQUIRE(msg);
        CHECK(streq(mlm_client_subject(email_client), "SENDMAIL_ALERT"));
        zuuid_str = zmsg_popstr(msg);
        zmsg_destroy(&msg);
        zclock_sleep(1000);

        //       7. send the reply to unblock the actor
        reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        mlm_client_sendto(email_client, FTY_ALERT_ACTIONS_TEST, "SENDMAIL_ALERT", NULL, 1000, &reply);

        zstr_free(&zuuid_str);
        zclock_sleep(1000);

        //      6. SMS SHOULD be generated
        msg = mlm_client_recv(email_client);
        REQUIRE(msg);
        CHECK(streq(mlm_client_subject(email_client), "SENDSMS_ALERT"));
        zuuid_str = zmsg_popstr(msg);
        zmsg_destroy(&msg);
        zclock_sleep(1000);

        //       7. send the reply to unblock the actor
        reply = zmsg_new();
        zmsg_addstr(reply, zuuid_str);
        zmsg_addstr(reply, "OK");
        mlm_client_sendto(email_client, FTY_ALERT_ACTIONS_TEST, "SENDSMS_ALERT", NULL, 1000, &reply);
        zclock_sleep(1000);

        zstr_free(&zuuid_str);

        //      8. send alert message again third time
        actions = zlist_new();
        zlist_autofree(actions);
        zlist_append(actions, static_cast<void*>(const_cast<char*>("EMAIL")));
        zlist_append(actions, static_cast<void*>(const_cast<char*>("SMS")));
        msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)), 600, rule_name8, asset_name8, "ACTIVE",
            "WARNING", "Default load in ups ROZ.UPS36 is high", actions);
        REQUIRE(msg);
        rv = mlm_client_send(alert_producer, alert_topic8.c_str(), &msg);
        REQUIRE(rv != -1);
        zlist_destroy(&actions);

        //      9. Email SHOULD NOT be generated
        zclock_sleep(1000);
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(email_client), NULL);
        void*      which  = zpoller_wait(poller, 1000);
        CHECK(which == NULL);
        zpoller_destroy(&poller);
    }
    //  @end
    mlm_client_destroy(&email_client);
    mlm_client_destroy(&alert_producer);
    mlm_client_destroy(&asset_producer);
    zactor_destroy(&alert_actions);
    zactor_destroy(&server);
}
