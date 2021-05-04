#include "autoconfig.h"
#include "fty_alert_engine_audit_log.h"
#include "fty_alert_engine_server.h"
#include "luarule.h"
#include <catch2/catch.hpp>
#include <cxxtools/directory.h>
#include <czmq.h>
#include <fty_shm.h>

static zmsg_t* s_poll_alert(mlm_client_t* consumer, const char* assetName, int timeout_ms = 5000)
{
    REQUIRE(consumer);
    zpoller_t* poller = zpoller_new(mlm_client_msgpipe(consumer), NULL);
    REQUIRE(poller);

    zmsg_t* recv = NULL; // ret value

    while (!zsys_interrupted) {
        void* which = zpoller_wait(poller, timeout_ms);
        if (!which)
            break;
        recv = mlm_client_recv(consumer);
        if (!recv)
            break;

        fty_proto_t* proto = fty_proto_decode(&recv);
        zmsg_destroy(&recv);

        if (proto && (fty_proto_id(proto) == FTY_PROTO_ALERT)) {
            if (!assetName || streq(assetName, fty_proto_name(proto))) {
                recv = fty_proto_encode(&proto); // gotcha!
                fty_proto_destroy(&proto);
                break;
            }
        }

        fty_proto_destroy(&proto);
    }

    zpoller_destroy(&poller);
    return recv;
}


TEST_CASE("Alert engine server")
{
    bool verbose = true;
    setenv("BIOS_LOG_PATTERN", "%D %c [%t] -%-5p- %M (%l) %m%n", 1);
    ManageFtyLog::setInstanceFtylog("fty-alert-engine-server");
    // Note: If your selftest reads SCMed fixture data, please keep it in
    // src/selftest-ro; if your test creates filesystem objects, please
    // do so under src/selftest-rw. They are defined below along with a
    // usecase (asert) to make compilers happy.
    const char* SELFTEST_DIR_RO = "test_rules";
    // const char* SELFTEST_DIR_RO = "src/selftest-ro";
    // const char* SELFTEST_DIR_RW = "src/selftest-rw";
    const char* SELFTEST_DIR_RW = "test_rules";
    REQUIRE(SELFTEST_DIR_RO);
    REQUIRE(SELFTEST_DIR_RW);
    std::string str_SELFTEST_DIR_RO = std::string(SELFTEST_DIR_RO);
    std::string str_SELFTEST_DIR_RW = std::string(SELFTEST_DIR_RW);

    log_info(" * fty_alert_engine_server: ");
    if (verbose)
        ManageFtyLog::getInstanceFtylog()->setVeboseMode();

    std::string logConfigFile = "src/fty-alert-engine-log.cfg";
    ManageFtyLog::getInstanceFtylog()->setConfigFile(logConfigFile);

    // initialize log for auditability
    AlertsEngineAuditLogManager::init(logConfigFile.c_str());

    int r = system(("rm -f " + str_SELFTEST_DIR_RW + "/*.rule").c_str());
    REQUIRE(r == 0); // to make gcc @ CentOS 7 happy

    //  @selftest
    static const char* endpoint = "inproc://fty-ag-server-test";

    zactor_t* server = zactor_new(mlm_server, static_cast<void*>(const_cast<char*>("Malamute")));
    zstr_sendx(server, "BIND", endpoint, NULL);

    //    mlm_client_t *producer = mlm_client_new ();
    //    mlm_client_connect (producer, endpoint, 1000, "producer");
    //    mlm_client_set_producer (producer, FTY_PROTO_STREAM_METRICS);

    mlm_client_t* consumer = mlm_client_new();
    mlm_client_connect(consumer, endpoint, 1000, "consumer");
    mlm_client_set_consumer(consumer, FTY_PROTO_STREAM_ALERTS_SYS, ".*");

    mlm_client_t* ui = mlm_client_new();
    mlm_client_connect(ui, endpoint, 1000, "UI");

    int polling_value = 2;
    int wanted_ttl    = polling_value + 2;
    fty_shm_set_default_polling_interval(polling_value);
    REQUIRE(fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str()) == 0);

    zactor_t* ag_server_stream =
        zactor_new(fty_alert_engine_stream, static_cast<void*>(const_cast<char*>("alert-stream")));
    zactor_t* ag_server_mail =
        zactor_new(fty_alert_engine_mailbox, static_cast<void*>(const_cast<char*>("fty-alert-engine")));

    zstr_sendx(ag_server_mail, "CONFIG", (str_SELFTEST_DIR_RW).c_str(), NULL);
    zstr_sendx(ag_server_mail, "CONNECT", endpoint, NULL);
    zstr_sendx(ag_server_mail, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);

    zstr_sendx(ag_server_stream, "CONNECT", endpoint, NULL);
    zstr_sendx(ag_server_stream, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);
    zstr_sendx(ag_server_stream, "CONSUMER", FTY_PROTO_STREAM_METRICS, ".*", NULL);
    zstr_sendx(ag_server_stream, "CONSUMER", FTY_PROTO_STREAM_METRICS_UNAVAILABLE, ".*", NULL);
    zclock_sleep(500); // THIS IS A HACK TO SETTLE DOWN THINGS

    // Test case #1: list w/o rules
    {
        zmsg_t* command = zmsg_new();
        zmsg_addstrf(command, "%s", "LIST");
        zmsg_addstrf(command, "%s", "all");
        zmsg_addstrf(command, "%s", "");
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &command);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 3);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "LIST"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "all"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, ""));
        zstr_free(&foo);
        zmsg_destroy(&recv);
    }

    // Test case #2.0: add new rule
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* simplethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/simplethreshold3.rule").c_str());
        REQUIRE(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);
    }

    // Test case #2.1: add new rule
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* simplethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/simplethreshold.rule").c_str());
        REQUIRE(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);
        // Test case #2.3: existing rule: simplethreshold
        //                 existing rule: simplethreshold2
        //                 update simplethreshold2 with new name simplethreshold
        rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        simplethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/simplethreshold2.rule").c_str());
        REQUIRE(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        simplethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/simplethreshold.rule").c_str());
        REQUIRE(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        zmsg_addstrf(rule, "%s", "simplethreshold2");
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "ALREADY_EXISTS"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);
        // Test case #5: generate alert - below the treshold
        //        zmsg_t *m = fty_proto_encode_metric (
        //            NULL, ::time (NULL), 0, "abc", "fff", "20", "X");
        REQUIRE(fty::shm::write_metric("fff", "abc", "20", "X", wanted_ttl) == 0);
        log_debug("first write ok !");
        //        mlm_client_send (producer, "abc@fff", &m);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());

        REQUIRE(is_fty_proto(recv));
        fty_proto_t* brecv = fty_proto_decode(&recv);
        REQUIRE(streq(fty_proto_rule(brecv), "simplethreshold"));
        REQUIRE(streq(fty_proto_name(brecv), "fff"));
        REQUIRE(streq(fty_proto_state(brecv), "ACTIVE"));
        REQUIRE(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);

        // Test case #6: generate alert - resolved
        //        m = fty_proto_encode_metric (
        //                NULL, time (NULL), 0, "abc", "fff", "42", "X");
        fty::shm::write_metric("fff", "abc", "42", "X", wanted_ttl);
        //        mlm_client_send (producer, "abc@fff", &m);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());

        REQUIRE(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        REQUIRE(streq(fty_proto_rule(brecv), "simplethreshold"));
        REQUIRE(streq(fty_proto_name(brecv), "fff"));
        REQUIRE(streq(fty_proto_state(brecv), "RESOLVED"));
        fty_proto_destroy(&brecv);
        // Test case #6: generate alert - high warning
        //        m = fty_proto_encode_metric (
        //                NULL, time (NULL), 0, "abc", "fff", "52", "X");
        fty::shm::write_metric("fff", "abc", "52", "X", wanted_ttl);
        //        mlm_client_send (producer, "abc@fff", &m);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());

        REQUIRE(recv);
        REQUIRE(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        REQUIRE(brecv);
        REQUIRE(streq(fty_proto_rule(brecv), "simplethreshold"));
        REQUIRE(streq(fty_proto_name(brecv), "fff"));
        REQUIRE(streq(fty_proto_state(brecv), "ACTIVE"));
        REQUIRE(streq(fty_proto_severity(brecv), "WARNING"));
        fty_proto_destroy(&brecv);
        // Test case #7: generate alert - high critical
        //        m = fty_proto_encode_metric (
        //                NULL, time (NULL), 0, "abc", "fff", "62", "X");
        fty::shm::write_metric("fff", "abc", "62", "X", wanted_ttl);
        //        mlm_client_send (producer, "abc@fff", &m);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());

        REQUIRE(recv);
        REQUIRE(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        REQUIRE(brecv);
        REQUIRE(streq(fty_proto_rule(brecv), "simplethreshold"));
        REQUIRE(streq(fty_proto_name(brecv), "fff"));
        REQUIRE(streq(fty_proto_state(brecv), "ACTIVE"));
        REQUIRE(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);
        // Test case #8: generate alert - resolved again
        //        m = fty_proto_encode_metric (
        //                NULL, time (NULL), 0, "abc", "fff", "42", "X");
        fty::shm::write_metric("fff", "abc", "42", "X", wanted_ttl);
        //        mlm_client_send (producer, "abc@fff", &m);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());

        REQUIRE(recv);
        REQUIRE(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        REQUIRE(brecv);
        REQUIRE(streq(fty_proto_rule(brecv), "simplethreshold"));
        REQUIRE(streq(fty_proto_name(brecv), "fff"));
        REQUIRE(streq(fty_proto_state(brecv), "RESOLVED"));
        fty_proto_destroy(&brecv);
        // Test case #9: generate alert - high again
        //        m = fty_proto_encode_metric (
        //                NULL, time (NULL), 0, "abc", "fff", "62", "X");
        //        mlm_client_send (producer, "abc@fff", &m);
        fty::shm::write_metric("fff", "abc", "62", "X", wanted_ttl);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());

        REQUIRE(recv);
        REQUIRE(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        REQUIRE(brecv);
        REQUIRE(streq(fty_proto_rule(brecv), "simplethreshold"));
        REQUIRE(streq(fty_proto_name(brecv), "fff"));
        REQUIRE(streq(fty_proto_state(brecv), "ACTIVE"));
        REQUIRE(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);
        // Test case #11: generate alert - high again
        //        m = fty_proto_encode_metric (
        //                NULL, time (NULL), 0, "abc", "fff", "62", "X");
        //        mlm_client_send (producer, "abc@fff", &m);
        fty::shm::write_metric("fff", "abc", "62", "X", wanted_ttl);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        REQUIRE(recv);
        REQUIRE(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        REQUIRE(brecv);
        REQUIRE(streq(fty_proto_rule(brecv), "simplethreshold"));
        REQUIRE(streq(fty_proto_name(brecv), "fff"));
        REQUIRE(streq(fty_proto_state(brecv), "ACTIVE"));
        REQUIRE(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);
        // Test case #12: generate alert - resolved
        //        m = fty_proto_encode_metric (
        //                NULL, time (NULL), 0, "abc", "fff", "42", "X");
        //        mlm_client_send (producer, "abc@fff", &m);
        fty::shm::write_metric("fff", "abc", "42", "X", wanted_ttl);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        REQUIRE(recv);
        REQUIRE(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        REQUIRE(brecv);
        REQUIRE(streq(fty_proto_rule(brecv), "simplethreshold"));
        REQUIRE(streq(fty_proto_name(brecv), "fff"));
        REQUIRE(streq(fty_proto_state(brecv), "RESOLVED"));
        fty_proto_destroy(&brecv);
    }

    // Test case #2.2: add new rule with existing name
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* simplethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/simplethreshold.rule").c_str());
        REQUIRE(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "ALREADY_EXISTS"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);
    }

    // Test case #2.3: add and delete new rule
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* simplethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/ups.rule").c_str());
        REQUIRE(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "DELETE");
        zmsg_addstrf(rule, "%s", "ups");
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "ups"));
        zstr_free(&foo);
        zmsg_destroy(&recv);
    }

    // Test case #2.4: delete unknown rule
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "DELETE");
        zmsg_addstrf(rule, "%s", "lkiuryt@fff");
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "NO_MATCH"));
        zstr_free(&foo);
        zmsg_destroy(&recv);
    }
    // Test case #3: list rules
    {
        zmsg_t* command = zmsg_new();
        zmsg_addstrf(command, "%s", "LIST");
        zmsg_addstrf(command, "%s", "all");
        zmsg_addstrf(command, "%s", "");
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &command);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 6);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "LIST"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "all"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, ""));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);
    }

    // Test case #4: list rules - not yet stored type
    {
        zmsg_t* command = zmsg_new();
        zmsg_addstrf(command, "%s", "LIST");
        zmsg_addstrf(command, "%s", "single");
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &command);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 3);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "LIST"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "single"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, ""));
        zstr_free(&foo);
        zmsg_destroy(&recv);
    }

    // Test case #4.1: list w/o rules
    {
        zmsg_t* command = zmsg_new();
        zmsg_addstrf(command, "%s", "LIST");
        zmsg_addstrf(command, "%s", "all");
        zmsg_addstrf(command, "%s", "example class");
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &command);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 4);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "LIST"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "all"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "example class"));
        zstr_free(&foo);
        zmsg_destroy(&recv);
    }

    // Test case #13: segfault on onbattery
    // #13.1 ADD new rule
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* onbattery_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/onbattery-5PX1500-01.rule").c_str());
        REQUIRE(onbattery_rule);
        zmsg_addstrf(rule, "%s", onbattery_rule);
        zstr_free(&onbattery_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);
        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);
        // #13.2 evaluate metric
        //        zmsg_t *m = fty_proto_encode_metric (
        //               NULL, ::time (NULL), ::time (NULL), "status.ups", "5PX1500-01", "1032.000", "");
        //        mlm_client_send (producer, "status.ups@5PX1500-01", &m);
        fty::shm::write_metric("5PX1500-01", "status.ups", "1032.000", "", wanted_ttl);
    }

    // Test case #14: add new rule, but with lua syntax error
    {
        log_info("######## Test case #14 add new rule, but with lua syntax error");
        zmsg_t* rule = zmsg_new();
        REQUIRE(rule);
        zmsg_addstrf(rule, "%s", "ADD");
        char* complexthreshold_rule_lua_error =
            s_readall((str_SELFTEST_DIR_RO + "/testrules/complexthreshold_lua_error.rule").c_str());
        REQUIRE(complexthreshold_rule_lua_error);
        zmsg_addstrf(rule, "%s", complexthreshold_rule_lua_error);
        zstr_free(&complexthreshold_rule_lua_error);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);
        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "BAD_LUA"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);
    }

    // Test case #15.1: add Radek's testing rule
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* toohigh_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/too_high-ROZ.ePDU13.rule").c_str());
        REQUIRE(toohigh_rule);
        zmsg_addstrf(rule, "%s", toohigh_rule);
        zstr_free(&toohigh_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        zmsg_destroy(&recv);

        // Test case #15.2: evaluate it
        //        zmsg_t *m = fty_proto_encode_metric (
        //                NULL, ::time (NULL), ::time (NULL), "status.ups", "ROZ.UPS33", "42.00", "");
        //        mlm_client_send (producer, "status.ups@ROZ.UPS33", &m);

        fty::shm::write_metric("ROZ.UPS33", "status.ups", "42.00", "", wanted_ttl);

        // get alert on ePDU13 (related to IPMVAL-2411 fix)
        recv = s_poll_alert(consumer, "ePDU13");

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());

        REQUIRE(recv);
        REQUIRE(is_fty_proto(recv));
        fty_proto_t* brecv = fty_proto_decode(&recv);
        REQUIRE(brecv);
        REQUIRE(streq(fty_proto_rule(brecv), "too_high-ROZ.ePDU13"));
        REQUIRE(streq(fty_proto_name(brecv), "ePDU13"));
        REQUIRE(streq(fty_proto_state(brecv), "ACTIVE"));
        REQUIRE(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);

        // Test case #15.3: evaluate it again
        //        m = fty_proto_encode_metric (
        //                NULL, ::time (NULL), ::time (NULL), "status.ups", "ROZ.UPS33", "42.00", "");
        //        mlm_client_send (producer, "status.ups@ROZ.UPS33", &m);
        fty::shm::write_metric("ROZ.UPS33", "status.ups", "42.00", "", wanted_ttl);

        // get alert on ePDU13 (related to IPMVAL-2411 fix)
        recv = s_poll_alert(consumer, "ePDU13");

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());

        REQUIRE(recv);
        REQUIRE(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        REQUIRE(brecv);
        REQUIRE(streq(fty_proto_rule(brecv), "too_high-ROZ.ePDU13"));
        REQUIRE(streq(fty_proto_name(brecv), "ePDU13"));
        REQUIRE(streq(fty_proto_state(brecv), "ACTIVE"));
        REQUIRE(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);
        zmsg_destroy(&recv);
    }

    // Test case #16.1: add new rule, with the trash at the end
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* rule_with_trash = s_readall((str_SELFTEST_DIR_RO + "/testrules/rule_with_trash.rule").c_str());
        REQUIRE(rule_with_trash);
        zmsg_addstrf(rule, "%s", rule_with_trash);
        zstr_free(&rule_with_trash);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        // Test case #16.2: add new rule, GET the rule with trash
        zmsg_t* command = zmsg_new();
        zmsg_addstrf(command, "%s", "GET");
        zmsg_addstrf(command, "%s", "rule_with_trash");
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &command);

        recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        std::stringstream           s{foo};
        cxxtools::JsonDeserializer  d{s};
        cxxtools::SerializationInfo si;
        d.deserialize(si);
        REQUIRE(si.memberCount() == 1);
        zstr_free(&foo);
        zmsg_destroy(&recv);
    }

    // test case #17 update the existing rule (type: threshold_simple)
    // input:
    //          * file check_update_threshold_simple.rule
    //          * file check_update_threshold_simple2.rule
    //      rules inside the files have the same names, but
    //      "values" are different
    // 1. add rule from the file check_update_threshold_simple.rule
    // 2. update "check_update_threshold_simple" rule with file "check_update_threshold_simple2.rule"
    //
    // expected result: SUCCESS
    // 1.
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* simplethreshold_rule =
            s_readall((str_SELFTEST_DIR_RO + "/testrules/check_update_threshold_simple.rule").c_str());
        REQUIRE(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        // 2.
        rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        simplethreshold_rule =
            s_readall((str_SELFTEST_DIR_RO + "/testrules/check_update_threshold_simple2.rule").c_str());
        REQUIRE(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        zmsg_addstrf(rule, "%s", "check_update_threshold_simple");
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        // check the result of the operation
        recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);
    }

    // ######## Test case #18
    // 18.1 add some rule (type: pattern)
    {
        log_info("######## Test case #18 add some rule (type: pattern)");
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* pattern_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/pattern.rule").c_str());
        REQUIRE(pattern_rule);
        zmsg_addstrf(rule, "%s", pattern_rule);
        zstr_free(&pattern_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);
        // 18.2 evaluate some rule (type: pattern)
        log_info("######## Test case #18.2 evaluate some rule (type: pattern)");
        //  18.2.1. OK
        //        zmsg_t *m = fty_proto_encode_metric (
        //                NULL, ::time (NULL), 24 * 60 * 60, "end_warranty_date", "UPS_pattern_rule", "100", "some
        //                description");
        //        mlm_client_send (producer, "end_warranty_date@UPS_pattern_rule", &m);
        fty::shm::write_metric("UPS_pattern_rule", "end_warranty_date", "100", "some description", wanted_ttl);

        // eat RESOLVED alert on UPS_pattern_rule (related to IPMVAL-2411 fix)
        recv = s_poll_alert(consumer, NULL);
        zmsg_destroy(&recv);

        // 18.2.1.1. No ALERT should be generated
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(consumer), NULL);
        void*      which  = zpoller_wait(poller, 2500);
        REQUIRE(which == NULL);
        log_debug("No alert was sent: SUCCESS");
        zpoller_destroy(&poller);

        // 18.2.2 LOW_WARNING
        //        m = fty_proto_encode_metric (
        //                NULL, ::time (NULL), 24 * 60 * 60, "end_warranty_date", "UPS_pattern_rule", "20", "some
        //                description");
        //        mlm_client_send (producer, "end_warranty_date@UPS_pattern_rule", &m);
        fty::shm::write_metric("UPS_pattern_rule", "end_warranty_date", "20", "some description", wanted_ttl);
        log_debug("18.2.2 LOW_WARNING : Wait for alert");
        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        REQUIRE(recv != NULL);
        REQUIRE(is_fty_proto(recv));
        fty_proto_t* brecv = fty_proto_decode(&recv);
        REQUIRE(streq(fty_proto_rule(brecv), "warranty2"));
        REQUIRE(streq(fty_proto_name(brecv), "UPS_pattern_rule"));
        REQUIRE(streq(fty_proto_state(brecv), "ACTIVE"));
        REQUIRE(streq(fty_proto_severity(brecv), "WARNING"));
        fty_proto_destroy(&brecv);

        // 18.2.3 LOW_CRITICAL
        //        m = fty_proto_encode_metric (
        //                NULL, ::time (NULL), 24 * 60 * 60, "end_warranty_date", "UPS_pattern_rule", "2", "some
        //                description");
        //        mlm_client_send (producer, "end_warranty_date@UPS_pattern_rule", &m);
        fty::shm::write_metric("UPS_pattern_rule", "end_warranty_date", "2", "some description", wanted_ttl);
        log_debug("18.2.3 LOW_CRITICAL : Wait for alert");
        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        REQUIRE(recv != NULL);
        REQUIRE(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        REQUIRE(streq(fty_proto_rule(brecv), "warranty2"));
        REQUIRE(streq(fty_proto_name(brecv), "UPS_pattern_rule"));
        REQUIRE(streq(fty_proto_state(brecv), "ACTIVE"));
        REQUIRE(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);

        zstr_free(&foo);
        zstr_free(&pattern_rule);
        zmsg_destroy(&recv);
    }

    // Test case #21:   Thresholds imported from devices
    {
        //      21.1.1  add existing rule: devicethreshold
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* devicethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/devicethreshold.rule").c_str());
        REQUIRE(devicethreshold_rule);
        zmsg_addstrf(rule, "%s", devicethreshold_rule);
        zstr_free(&devicethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        //      21.1.2  add existing rule second time: devicethreshold
        log_info("######## Test case #21.1.2 add existing rule second time: devicethreshold");
        rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        devicethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/devicethreshold2.rule").c_str());
        REQUIRE(devicethreshold_rule);
        zmsg_addstrf(rule, "%s", devicethreshold_rule);
        zstr_free(&devicethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "ALREADY_EXISTS"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        //      21.2  update existing rule
        rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        devicethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/devicethreshold2.rule").c_str());
        REQUIRE(devicethreshold_rule);
        zmsg_addstrf(rule, "%s", devicethreshold_rule);
        zstr_free(&devicethreshold_rule);
        zmsg_addstrf(rule, "%s", "device_threshold_test"); // name of the rule
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        //      21.3  check that alert is not generated

        //        zmsg_t *m = fty_proto_encode_metric (
        //                NULL, ::time (NULL), 600, "device_metric", "ggg", "100", "");
        //        mlm_client_send (producer, "device_metric@ggg", &m);
        fty::shm::write_metric("ggg", "device_metric", "100", "", wanted_ttl);

        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(consumer), NULL);
        void*      which  = zpoller_wait(poller, polling_value * 3);
        REQUIRE(which == NULL);
        if (verbose) {
            log_debug("No alert was sent: SUCCESS");
        }
        zpoller_destroy(&poller);
    }

    // Test 22: a simple threshold with not double value
    // actually, this "behaviour" would automatically apply to ALL rules,
    // as it is implemented in rule.class
    // 22-1 : "A40"
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstr(rule, "ADD");
        char* simplethreshold_rule =
            s_readall((str_SELFTEST_DIR_RO + "/testrules/simplethreshold_string_value1.rule").c_str());
        REQUIRE(simplethreshold_rule);
        zmsg_addstr(rule, simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        log_info(foo);
        REQUIRE(streq(foo, "BAD_JSON"));
        zstr_free(&foo);
        zmsg_destroy(&recv);

        // 22-2 : "20AA"
        /*
            // 22-2 : "50AA"
            log_info ("######## Test case #22-2 a simple threshold with not double value (50AA)");
        */
        rule = zmsg_new();
        zmsg_addstr(rule, "ADD");
        simplethreshold_rule =
            s_readall((str_SELFTEST_DIR_RO + "/testrules/simplethreshold_string_value2.rule").c_str());
        REQUIRE(simplethreshold_rule);
        zmsg_addstr(rule, simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        log_info(foo);
        REQUIRE(streq(foo, "BAD_JSON"));
        zstr_free(&foo);
        zmsg_destroy(&recv);
    }

    // test 23: touch rule, that doesn't exist
    {
        log_info("######## Test case #23: touch rule, that doesn't exist");
        zmsg_t* touch_request = zmsg_new();
        REQUIRE(touch_request);
        zmsg_addstr(touch_request, "TOUCH");
        zmsg_addstr(touch_request, "rule_to_touch_doesnt_exists");
        int rv = mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &touch_request);
        REQUIRE(rv == 0);

        zmsg_t* recv = mlm_client_recv(ui);
        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "NOT_FOUND"));
        zstr_free(&foo);
        zmsg_destroy(&recv);
    }

    // test 24: touch rule that exists
    {
        // 24.1 Create a rule we are going to test against
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* rule_to_touch = s_readall((str_SELFTEST_DIR_RO + "/testrules/rule_to_touch.rule").c_str());
        REQUIRE(rule_to_touch);
        zmsg_addstrf(rule, "%s", rule_to_touch);
        zstr_free(&rule_to_touch);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        // 24.1.1 there is no any alerts on the rule; send touch request
        zmsg_t* touch_request = zmsg_new();
        REQUIRE(touch_request);
        zmsg_addstr(touch_request, "TOUCH");
        zmsg_addstr(touch_request, "rule_to_touch");
        int rv = mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &touch_request);
        REQUIRE(rv == 0);

        recv = mlm_client_recv(ui);
        REQUIRE(recv);
        REQUIRE(zmsg_size(recv) == 1);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        zmsg_destroy(&recv);

        // 24.1.2 No ALERT should be generated/regenerated/closed
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(consumer), NULL);
        REQUIRE(poller);
        void* which = zpoller_wait(poller, polling_value * 2);
        REQUIRE(which == NULL);
        if (verbose) {
            log_debug("No alert was sent: SUCCESS");
        }
        zpoller_destroy(&poller);

        // 24.2.1.1 there exists ACTIVE alert (as there were no alerts, lets create one :)); send metric
        //        zmsg_t *m = fty_proto_encode_metric (
        //                NULL, ::time (NULL), 0, "metrictouch", "assettouch", "10", "X");
        //        REQUIRE (m);
        //        rv = mlm_client_send (producer, "metrictouch@assettouch", &m);
        fty::shm::write_metric("assettouch", "metrictouch", "10", "X", wanted_ttl);
        REQUIRE(rv == 0);

        // 24.2.1.2 receive alert
        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        REQUIRE(recv);
        REQUIRE(is_fty_proto(recv));
        fty_proto_t* brecv = fty_proto_decode(&recv);
        REQUIRE(brecv);
        REQUIRE(streq(fty_proto_rule(brecv), "rule_to_touch"));
        REQUIRE(streq(fty_proto_name(brecv), "assettouch"));
        REQUIRE(streq(fty_proto_state(brecv), "ACTIVE"));
        REQUIRE(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);

        // 24.2.2 send touch request
        touch_request = zmsg_new();
        REQUIRE(touch_request);
        zmsg_addstr(touch_request, "TOUCH");
        zmsg_addstr(touch_request, "rule_to_touch");
        rv = mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &touch_request);
        REQUIRE(rv == 0);

        recv = mlm_client_recv(ui);
        REQUIRE(recv);
        REQUIRE(zmsg_size(recv) == 1);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        zmsg_destroy(&recv);

        // 24.2.3 the only existing ALERT must be RESOLVED
        poller = zpoller_new(mlm_client_msgpipe(consumer), NULL);
        REQUIRE(poller);
        which = zpoller_wait(poller, polling_value * 2);
        REQUIRE(which != NULL);
        recv = mlm_client_recv(consumer);
        REQUIRE(recv != NULL);
        REQUIRE(is_fty_proto(recv));
        if (verbose) {
            brecv = fty_proto_decode(&recv);
            REQUIRE(streq(fty_proto_rule(brecv), "rule_to_touch"));
            REQUIRE(streq(fty_proto_name(brecv), "assettouch"));
            REQUIRE(streq(fty_proto_state(brecv), "RESOLVED"));
            REQUIRE(streq(fty_proto_severity(brecv), "CRITICAL"));
            fty_proto_destroy(&brecv);
            log_debug("Alert was sent: SUCCESS");
        }
        zmsg_destroy(&recv);
        zpoller_destroy(&poller);

        // 24.3.1: there exists a RESOLVED alert for this rule; send touch request
        touch_request = zmsg_new();
        REQUIRE(touch_request);
        zmsg_addstr(touch_request, "TOUCH");
        zmsg_addstr(touch_request, "rule_to_touch");
        rv = mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &touch_request);
        REQUIRE(rv == 0);

        recv = mlm_client_recv(ui);
        REQUIRE(recv);
        REQUIRE(zmsg_size(recv) == 1);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        zmsg_destroy(&recv);

        // 24.3.2 NO alert should be generated
        poller = zpoller_new(mlm_client_msgpipe(consumer), NULL);
        REQUIRE(poller);
        which = zpoller_wait(poller, polling_value * 2);
        REQUIRE(which == NULL);
        if (verbose) {
            log_debug("No alert was sent: SUCCESS");
        }
        zpoller_destroy(&poller);
    }

    // test 25: metric_unavailable
    // 25.1 Create a rules we are going to test against; add First rule
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* rule_to_touch = s_readall((str_SELFTEST_DIR_RO + "/testrules/rule_to_metrictouch1.rule").c_str());
        REQUIRE(rule_to_touch);
        zmsg_addstrf(rule, "%s", rule_to_touch);
        zstr_free(&rule_to_touch);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        // 25.2 Add Second rule
        rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        rule_to_touch = s_readall((str_SELFTEST_DIR_RO + "/testrules/rule_to_metrictouch2.rule").c_str());
        REQUIRE(rule_to_touch);
        zmsg_addstrf(rule, "%s", rule_to_touch);
        zstr_free(&rule_to_touch);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        recv = mlm_client_recv(ui);

        REQUIRE(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        // 25.3.1 Generate alert on the First rule; send metric
        //        zmsg_t *m = fty_proto_encode_metric (
        //                NULL, ::time (NULL), 0, "metrictouch1", "element1", "100", "X");
        //        REQUIRE (m);
        //        int rv = mlm_client_send (producer, "metrictouch1@element1", &m);
        int rv = fty::shm::write_metric("element1", "metrictouch1", "100", "X", wanted_ttl);
        REQUIRE(rv == 0);

        // 25.3.2 receive alert
        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        REQUIRE(recv);
        REQUIRE(is_fty_proto(recv));
        fty_proto_t* brecv = fty_proto_decode(&recv);
        fty_proto_print(brecv);
        REQUIRE(brecv);
        REQUIRE(streq(fty_proto_rule(brecv), "rule_to_metrictouch1"));
        REQUIRE(streq(fty_proto_name(brecv), "element3"));
        REQUIRE(streq(fty_proto_state(brecv), "ACTIVE"));
        REQUIRE(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);

        // 25.4.1 Generate alert on the Second rule; send metric
        //        m = fty_proto_encode_metric (
        //                NULL, ::time (NULL), 0, "metrictouch2", "element2", "80", "X");
        //        REQUIRE (m);
        //        rv = mlm_client_send (producer, "metrictouch2@element2", &m);
        rv = fty::shm::write_metric("element2", "metrictouch2", "80", "X", wanted_ttl);
        REQUIRE(rv == 0);

        // 25.4.2 receive alert
        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        REQUIRE(recv);
        REQUIRE(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        REQUIRE(brecv);
        REQUIRE(streq(fty_proto_rule(brecv), "rule_to_metrictouch2"));
        REQUIRE(streq(fty_proto_name(brecv), "element3"));
        REQUIRE(streq(fty_proto_state(brecv), "ACTIVE"));
        REQUIRE(streq(fty_proto_severity(brecv), "WARNING"));
        fty_proto_destroy(&brecv);

        // 25.5 Send "metric unavailable"
        // 25.5.1. We need a special client for this
        mlm_client_t* metric_unavailable = mlm_client_new();
        mlm_client_connect(metric_unavailable, endpoint, 1000, "metricunavailable");
        mlm_client_set_producer(metric_unavailable, "_METRICS_UNAVAILABLE");

        // 25.5.2. send UNAVAILABLE metric
        zmsg_t* m_unavailable = zmsg_new();
        REQUIRE(m_unavailable);
        zmsg_addstr(m_unavailable, "METRICUNAVAILABLE");
        zmsg_addstr(m_unavailable, "metrictouch1@element1");

        rv = mlm_client_send(metric_unavailable, "metrictouch1@element1", &m_unavailable);
        REQUIRE(rv == 0);

        // 25.6 Check that 2 alerts were resolved
        recv = mlm_client_recv(consumer);
        REQUIRE(recv);
        REQUIRE(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        REQUIRE(brecv);
        REQUIRE(streq(fty_proto_state(brecv), "RESOLVED"));
        fty_proto_destroy(&brecv);

        recv = mlm_client_recv(consumer);
        REQUIRE(recv);
        REQUIRE(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        REQUIRE(brecv);
        REQUIRE(streq(fty_proto_name(brecv), "element3"));
        REQUIRE(streq(fty_proto_state(brecv), "RESOLVED"));
        fty_proto_destroy(&brecv);

        // 25.7 clean up
        mlm_client_destroy(&metric_unavailable);
    }

    // # 26 - # 30 : test autoconfig
    mlm_client_t* asset_producer = mlm_client_new();
    REQUIRE(asset_producer);
    mlm_client_connect(asset_producer, endpoint, 1000, "asset_producer");
    mlm_client_set_producer(asset_producer, FTY_PROTO_STREAM_ASSETS);

    zactor_t* ag_configurator = zactor_new(autoconfig, static_cast<void*>(const_cast<char*>("test-autoconfig")));
    REQUIRE(ag_configurator);
    zstr_sendx(ag_configurator, "CONFIG", SELFTEST_DIR_RW, NULL);
    zstr_sendx(ag_configurator, "CONNECT", endpoint, NULL);
    zstr_sendx(ag_configurator, "TEMPLATES_DIR", (str_SELFTEST_DIR_RO + "/templates").c_str(), NULL);
    zstr_sendx(ag_configurator, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    zstr_sendx(ag_configurator, "ALERT_ENGINE_NAME", "fty-alert-engine", NULL);
    zclock_sleep(500); // THIS IS A HACK TO SETTLE DOWN THINGS

#if 0 // deactivated, works with FTY_PROTO_STREAM_ASSETS/create and seems to have some issues
    // # 26.1 catch message 'create asset', check that we created rules
    {
        zhash_t *aux = zhash_new ();
        zhash_autofree (aux);
        zhash_insert (aux, "type", (void *) "datacenter");
        zhash_insert (aux, "priority", (void *) "P1");
        zmsg_t *m = fty_proto_encode_asset (aux,
                "test",
                FTY_PROTO_ASSET_OP_CREATE,
                NULL);
        REQUIRE (m);
        zhash_destroy (&aux);
        int rv = mlm_client_send (asset_producer, "datacenter.@test", &m);
        REQUIRE ( rv == 0 );

        zclock_sleep (20000);

        char *average_humidity = s_readall ((str_SELFTEST_DIR_RW + "/average.humidity@test.rule").c_str ());
        REQUIRE (average_humidity);
        char *average_temperature = s_readall ((str_SELFTEST_DIR_RW + "/average.temperature@test.rule").c_str ());
        REQUIRE (average_temperature);
        char *realpower_default =  s_readall ((str_SELFTEST_DIR_RW + "/realpower.default@test.rule").c_str ());
        REQUIRE (realpower_default);
        char *phase_imbalance = s_readall ((str_SELFTEST_DIR_RW + "/phase_imbalance@test.rule").c_str ());
        REQUIRE (phase_imbalance);

        zstr_free (&realpower_default);
        zstr_free (&phase_imbalance);
        zstr_free (&average_humidity);
        zstr_free (&average_temperature);
        // # 26.2 force an alert
        int ttl = wanted_ttl;
//        m = fty_proto_encode_metric (
//            NULL, ::time (NULL), ttl, "average.temperature", "test", "1000", "C");
//        REQUIRE (m);
//        rv = mlm_client_send (producer, "average.temperature@test", &m);
        rv = fty::shm::write_metric("test", "average.temperature", "1000", "C", ttl);
        REQUIRE ( rv == 0 );

        zmsg_t *recv = mlm_client_recv (consumer);

    fty_shm_delete_test_dir();
    fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        REQUIRE (recv);
        REQUIRE (is_fty_proto (recv));
        fty_proto_t *brecv = fty_proto_decode (&recv);
        REQUIRE (brecv);
        ttl = fty_proto_ttl (brecv);
        REQUIRE (ttl != -1);
        REQUIRE (streq (fty_proto_rule (brecv), "average.temperature@test"));
        REQUIRE (streq (fty_proto_name (brecv), "test"));
        REQUIRE (streq (fty_proto_state (brecv), "ACTIVE"));
        REQUIRE (streq (fty_proto_severity (brecv), "CRITICAL"));
        fty_proto_destroy (&brecv);
    }

    // # 27.1 update the created asset, check that we have the rules, wait for 3*ttl,
    // refresh the metric, check that we still have the alert
    {
        zhash_t *aux2 = zhash_new ();
        zhash_autofree (aux2);
        zhash_insert (aux2, "type", (void *) "row");
        zhash_insert (aux2, "priority", (void *) "P2");
        zmsg_t *m = fty_proto_encode_asset (aux2,
                        "test",
                        FTY_PROTO_ASSET_OP_UPDATE,
                        NULL);
        REQUIRE (m);
        zhash_destroy (&aux2);
        int rv = mlm_client_send (asset_producer, "row.@test", &m);
        REQUIRE ( rv == 0 );

        zclock_sleep (20000);

        char *average_humidity = s_readall ((str_SELFTEST_DIR_RW + "/average.humidity@test.rule").c_str ());
        REQUIRE (average_humidity);
        char *average_temperature = s_readall ((str_SELFTEST_DIR_RW + "/average.temperature@test.rule").c_str ());
        REQUIRE (average_temperature);

        zstr_free (&average_humidity);
        zstr_free (&average_temperature);
        // TODO: now inapplicable rules should be deleted in the future
        /* realpower_default =  s_readall ((str_SELFTEST_DIR_RW + "/realpower.default@test.rule").c_str ());
        phase_imbalance = s_readall ((str_SELFTEST_DIR_RW + "/phase.imbalance@test.rule").c_str ());
        REQUIRE (realpower_default == NULL && phase_imbalance == NULL); */

        int ttl = wanted_ttl;
        zclock_sleep (3 * ttl);
//        m = fty_proto_encode_metric (
//            NULL, ::time (NULL), ttl, "average.temperature", "test", "1000", "C");
//        REQUIRE (m);
//        rv = mlm_client_send (producer, "average.temperature@test", &m);
        fty::shm::write_metric("test", "average.temperature", "1000", "C", ttl);
        REQUIRE ( rv == 0 );

        zmsg_t *recv = mlm_client_recv (consumer);

    fty_shm_delete_test_dir();
    fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        REQUIRE ( recv != NULL );
        REQUIRE ( is_fty_proto (recv));
        fty_proto_t *brecv = fty_proto_decode (&recv);
        REQUIRE (streq (fty_proto_rule (brecv), "average.temperature@test"));
        REQUIRE (streq (fty_proto_name (brecv), "test"));
        REQUIRE (streq (fty_proto_state (brecv), "ACTIVE"));
        REQUIRE (streq (fty_proto_severity (brecv), "CRITICAL"));
        if (verbose) {
            log_debug ("Alert was sent: SUCCESS");
        }
        fty_proto_destroy (&brecv);
    }
#endif
    // Test case #30: list templates rules
    {
        log_debug("Test #30 ..");
        zmsg_t* command = zmsg_new();
        zmsg_addstrf(command, "%s", "LIST");
        zmsg_addstrf(command, "%s", "123456");
        zmsg_addstrf(command, "%s", "all");
        mlm_client_sendto(ui, "test-autoconfig", "rfc-evaluator-rules", NULL, 1000, &command);

        zmsg_t* recv = mlm_client_recv(ui);

        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "123456"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "LIST"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "all"));
        zstr_free(&foo);

        cxxtools::Directory d((str_SELFTEST_DIR_RO + "/templates").c_str());
        int                 file_counter = 0;
        char*               template_name;
        for (const auto& fn : d) {
            if (fn.compare(".") != 0 && fn.compare("..") != 0) {
                // read the template rule from the file
                std::ifstream f(d.path() + "/" + fn);
                std::string   str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                template_name = zmsg_popstr(recv);
                REQUIRE(fn.compare(template_name) == 0);
                // template content
                foo = zmsg_popstr(recv);
                REQUIRE(str.compare(foo) == 0);
                zstr_free(&foo);
                // element list
                foo = zmsg_popstr(recv);
#if 0 // related to 'test' asset created w/ fty-asset (see above)
                if (fn.find ("__row__")!= std::string::npos){
                    log_debug ("template: '%s', devices :'%s'",template_name,foo);
                    REQUIRE (streq (foo,"test"));
                }
#endif
                file_counter++;
                zstr_free(&foo);
                zstr_free(&template_name);
            }
        }
        REQUIRE(file_counter > 0);
        log_debug("Test #30 : List All templates parse successfully %d files", file_counter);
        zmsg_destroy(&recv);
    }

    // Test case #20 update some rule (type: pattern)
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* pattern_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/pattern.rule").c_str());
        REQUIRE(pattern_rule);
        zmsg_addstrf(rule, "%s", pattern_rule);
        zmsg_addstrf(rule, "%s", "warranty2");
        zstr_free(&pattern_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);
        REQUIRE(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        REQUIRE(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        // recieve an alert
        recv = mlm_client_recv(consumer);
        REQUIRE(recv != NULL);
        REQUIRE(is_fty_proto(recv));
        fty_proto_t* brecv = fty_proto_decode(&recv);
        fty_proto_destroy(&brecv);
    }

    // utf8eq
    {
        static const std::vector<std::string> strings{"ŽlUťOUčKý kůň",
            "\u017dlu\u0165ou\u010dk\xc3\xbd K\u016f\xc5\x88", "Žluťou\u0165ký kůň", "ŽLUťou\u0165Ký kůň",
            "Ka\xcc\x81rol", "K\xc3\xa1rol", "супер test", "\u0441\u0443\u043f\u0435\u0440 Test"};

        REQUIRE(utf8eq(strings[0], strings[1]) == 1);
        REQUIRE(utf8eq(strings[0], strings[2]) == 0);
        REQUIRE(utf8eq(strings[1], strings[2]) == 0);
        REQUIRE(utf8eq(strings[2], strings[3]) == 1);
        REQUIRE(utf8eq(strings[4], strings[5]) == 0);
        REQUIRE(utf8eq(strings[6], strings[7]) == 1);
    }

    log_debug("Cleanup");

    zclock_sleep(3000);
    zactor_destroy(&ag_configurator);
    zactor_destroy(&ag_server_stream);
    zactor_destroy(&ag_server_mail);
    clearEvaluateMetrics();
    mlm_client_destroy(&asset_producer);
    mlm_client_destroy(&ui);
    mlm_client_destroy(&consumer);
    fty_shm_delete_test_dir();
    zactor_destroy(&server);

    // release audit context
    AlertsEngineAuditLogManager::deinit();

    //  @end
    printf("OK\n");
}