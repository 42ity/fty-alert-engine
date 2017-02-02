/*  =========================================================================
    fty_alert_engine_configurator - Configurator for fty-alert-engine

    Copyright (C) 2014 - 2015 Eaton                                        
                                                                           
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
    =========================================================================
*/

/*
@header
    fty_alert_engine_configurator - Configurator for fty-alert-engine
@discuss
@end
*/
extern int agent_alert_verbose;

#include "fty_alert_engine_classes.h"

//  --------------------------------------------------------------------------
//  fty_alert_engine_configurator actor

void
fty_alert_engine_configurator (zsock_t *pipe, void *args)
{
    char *name = (char*) args;

    MetricList cache; // need to track incoming measurements
    AlertConfiguration alertConfiguration;
    mlm_client_t *client = mlm_client_new ();
    assert (client);

    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (client), NULL);
    assert (poller);

    uint64_t timeout = 30000;

    zsock_signal (pipe, 0);

    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, timeout);
        if (which == NULL) {
            if (zpoller_terminated (poller) || zsys_interrupted) {
                zsys_warning ("%s: zpoller_terminated () or zsys_interrupted. Shutting down.", name);
                break;
            }
            if (zpoller_expired (poller)) {
            }
            continue;
        }

        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            char *cmd = zmsg_popstr (msg);

            if (streq (cmd, "$TERM")) {
                zsys_debug1 ("%s: $TERM received", name);
                zstr_free (&cmd);
                zmsg_destroy (&msg);
                break;
            }
            else
            if (streq (cmd, "VERBOSE")) {
                zsys_debug1 ("%s: VERBOSE received", name);
                agent_alert_verbose = true;
            }
            else
            if (streq (cmd, "CONNECT")) {
                zsys_debug1 ("CONNECT received");
                char* endpoint = zmsg_popstr (msg);
                int rv = mlm_client_connect (client, endpoint, 1000, name);
                if (rv == -1)
                    zsys_error ("%s: can't connect to malamute endpoint '%s'", name, endpoint);
                zstr_free (&endpoint);
            }
            else
            if (streq (cmd, "CONSUMER")) {
                zsys_debug1 ("CONSUMER received");
                char* stream = zmsg_popstr (msg);
                char* pattern = zmsg_popstr (msg);
                int rv = mlm_client_set_consumer (client, stream, pattern);
                if (rv == -1)
                    zsys_error ("%s: can't set consumer on stream '%s', '%s'", name, stream, pattern);
                zstr_free (&pattern);
                zstr_free (&stream);
            }
            else
            if (streq (cmd, "TEMPLATES_DIR")) {
                zsys_debug1 ("TEMPLATES_DIR received");
                char* dirname = zmsg_popstr (msg);
                if (dirname) {
                    alertConfiguration.setTemplatesDir(dirname);
                }
                else {
                    zsys_error ("%s: in TEMPLATES_DIR command next frame is missing", name);
                }
                zstr_free (&dirname);
            }
            zstr_free (&cmd);
            zmsg_destroy (&msg);
            continue;
            }

        zmsg_t *zmessage = mlm_client_recv (client);
        if ( zmessage == NULL ) {
            continue;
        }
        std::string topic = mlm_client_subject(client);
        
        if ( is_fty_proto(zmessage) ) {
            fty_proto_t *bmessage = fty_proto_decode(&zmessage);
            if( ! bmessage ) {
                zsys_error ("%s: can't decode message with topic %s, ignoring", name, topic.c_str());
                continue;
            }
            if (fty_proto_id (bmessage) == FTY_PROTO_ASSET) {
                std::vector <PureAlert> alertsToSend {};

                const char *name = fty_proto_name (bmessage);
                const char *operation = fty_proto_operation (bmessage);

                const char *status = fty_proto_aux_string (bmessage, "status", NULL);
                if (status != NULL && !streq (status, "active") ) {
                    if (!(streq (operation, FTY_PROTO_ASSET_OP_DELETE) || streq (operation, FTY_PROTO_ASSET_OP_RETIRE))) {
                        alertConfiguration.resolveAlertsForAsset (name, alertsToSend);
                        continue;
                    }
                }

                if (streq (operation, FTY_PROTO_ASSET_OP_CREATE)) {
                    const char *type = fty_proto_aux_string (bmessage, "type", NULL);
                    if (type == NULL) {
                        zsys_warning ("received asset message without type, no rules created for asset '%s'", name);
                        continue;
                    }
                    const char *subtype = fty_proto_aux_string (bmessage, "subtype", NULL);
                    alertConfiguration.generateRulesForAsset (client, type, subtype, name);
                }
                else if (streq (operation, FTY_PROTO_ASSET_OP_UPDATE)) {
                    // delete correspoding rules, mark all alerts corresponding to this asset as resolved
                    alertConfiguration.removeRulesForAsset (name, alertsToSend);
                    // generate new rules
                    const char *type = fty_proto_aux_string (bmessage, "type", NULL);
                    if (type == NULL) {
                        zsys_warning ("received asset message without type, no rules created for asset '%s'", name);
                        continue;
                    }
                    const char *subtype = fty_proto_aux_string (bmessage, "subtype", NULL);
                    alertConfiguration.generateRulesForAsset (client, type, subtype, name);
                    // re-evaluate all rules
                    alertConfiguration.evaluateRulesForAsset (client, name, cache);
                }
                else if (streq (operation, FTY_PROTO_ASSET_OP_DELETE) || streq (operation, FTY_PROTO_ASSET_OP_RETIRE)) {
                    // delete correspoding rules, mark all alerts corresponding to this asset as resolved
                    alertConfiguration.removeRulesForAsset (name, alertsToSend);
                }
                else if (streq (operation, FTY_PROTO_ASSET_OP_INVENTORY)) {
                    // do nothing (yet)
                }
                else {
                    zsys_error ("received asset message for asset '%s' with invalid operation %s, ignore message", name, operation);
                    continue;
                }
            }
            else {
                zsys_error ("received message with unexpected id %d, ignore message", fty_proto_id (bmessage));
                continue;
            }
            fty_proto_destroy (&bmessage);
        }
    }
    zpoller_destroy (&poller);
    mlm_client_destroy (&client);
}

//  --------------------------------------------------------------------------
//  Self test of this class

static char*
s_readall (const char* filename) {
    FILE *fp = fopen(filename, "rt");
    if (!fp)
        return NULL;

    size_t fsize = 0;
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *ret = (char*) malloc (fsize * sizeof (char) + 1);
    if (!ret) {
        fclose (fp);
        return NULL;
    }
    memset ((void*) ret, '\0', fsize * sizeof (char) + 1);

    size_t r = fread((void*) ret, 1, fsize, fp);
    fclose (fp);
    if (r == fsize)
        return ret;

    free (ret);
    return NULL;
}

void
fty_alert_engine_configurator_test (bool verbose)
{
    printf (" * fty_alert_engine_configurator: ");

    //  @selftest
    int r = system ("rm -f src/*.rule");
    assert (r == 0); // to make gcc @ CentOS 7 happy

    //  @selftest
    static const char* endpoint = "inproc://fty-ag-configurator-test";

    zactor_t *server = zactor_new (mlm_server, (void*) "Malamute");
    zstr_sendx (server, "BIND", endpoint, NULL);
    if (verbose)
        zstr_send (server, "VERBOSE");

    mlm_client_t *producer = mlm_client_new ();
    mlm_client_connect (producer, endpoint, 1000, "producer");
    mlm_client_set_producer (producer, FTY_PROTO_STREAM_METRICS);

    mlm_client_t *consumer = mlm_client_new ();
    mlm_client_connect (consumer, endpoint, 1000, "consumer");
    mlm_client_set_consumer (consumer, FTY_PROTO_STREAM_ALERTS_SYS, ".*");
    
    mlm_client_t *asset_producer = mlm_client_new ();
    mlm_client_connect (asset_producer, endpoint, 1000, "asset_producer");
    mlm_client_set_producer (asset_producer, FTY_PROTO_STREAM_ASSETS);
    
    zactor_t *ag_configurator = zactor_new (fty_alert_engine_server, (void*) "alert-agent");
    if (verbose)
        zstr_send (ag_configurator, "VERBOSE");
    zstr_sendx (ag_configurator, "CONNECT", endpoint, NULL);
    zstr_sendx (ag_configurator, "TEMPLATES_DIR", "src/templates", NULL);
    zstr_sendx (ag_configurator, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    zclock_sleep (500);   //THIS IS A HACK TO SETTLE DOWN THINGS
    
    // 1 catch message 'create asset', check that we created rules

    zhash_t *aux = zhash_new ();
    zhash_autofree (aux);
    zhash_insert (aux, "type", (void *) "dc");
    zhash_insert (aux, "priority", (void *) "P1");
    zmsg_t * m = fty_proto_encode_asset (aux,
            "test",
            FTY_PROTO_ASSET_OP_CREATE,
            NULL);
    assert (m);
    int rv = mlm_client_send (asset_producer, "dc.@test", &m);
    assert ( rv == 0 );

    zclock_sleep (3000);

    char *average_humidity = s_readall ((std::string ("src/testrules") + "/average.humidity@test.rule").c_str ());
    assert (average_humidity);
    char *average_temperature = s_readall ((std::string ("src/testrules") + "/average.temperature@test.rule").c_str ());
    assert (average_temperature);
    char *realpower_default =  s_readall ((std::string ("src/testrules") + "/realpower.default@test.rule").c_str ());
    assert (realpower_default);
    char *phase_imbalance = s_readall ((std::string ("src/testrules") + "/phase.imbalance@test.rule").c_str ());
    assert (phase_imbalance);

    // force an alert
    m = fty_proto_encode_metric (
            NULL, "average.temperature", "test", "1000", "C", 0);
    assert (m);
    rv = mlm_client_send (producer, "average.temperature@test", &m);
    assert ( rv == 0 );

    zmsg_t *recv = mlm_client_recv (consumer);
    assert (recv);
    assert (is_fty_proto (recv));
    fty_proto_t *brecv = fty_proto_decode (&recv);
    assert (brecv);
    int ttl = fty_proto_aux_number (brecv, "TTL", -1);
    assert (ttl != -1);
    assert (streq (fty_proto_rule (brecv), "average.temperature@test.rule"));
    assert (streq (fty_proto_element_src (brecv), "test"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    fty_proto_destroy (&brecv);

    // 27.1 update the created asset to something similar, wait for 3*ttl, check that we have the rules and alerts are the same

    zhash_t *aux2 = zhash_new ();
    zhash_autofree (aux2);
    zhash_insert (aux2, "type", (void *) "dc");
    zhash_insert (aux2, "priority", (void *) "P2");
    m = fty_proto_encode_asset (aux2,
            "test",
            FTY_PROTO_ASSET_OP_UPDATE,
            NULL);
    assert (m);
    rv = mlm_client_send (asset_producer, "dc.@test", &m);
    assert ( rv == 0 );

    average_humidity = s_readall ((std::string ("src/testrules") + "/average.humidity@test.rule").c_str ());
    assert (average_humidity);
    average_temperature = s_readall ((std::string ("src/testrules") + "/average.temperature@test.rule").c_str ());
    assert (average_temperature);
    realpower_default =  s_readall ((std::string ("src/testrules") + "/realpower.default@test.rule").c_str ());
    assert (realpower_default);
    phase_imbalance = s_readall ((std::string ("src/testrules") + "/phase.imbalance@test.rule").c_str ());
    assert (phase_imbalance);

    zstr_free (&average_humidity);
    zstr_free (&average_temperature);
    zstr_free (&realpower_default);
    zstr_free (&phase_imbalance);

    zpoller_t *poller = zpoller_new (mlm_client_msgpipe (consumer), NULL);
    assert (poller);
    void *which = zpoller_wait (poller, 3*ttl);
    assert ( which != NULL );
    recv = mlm_client_recv (consumer);
    assert ( recv != NULL );
    assert ( is_fty_proto (recv));
    if ( verbose ) {
        brecv = fty_proto_decode (&recv);
        fty_proto_destroy (&brecv);
        assert (streq (fty_proto_rule (brecv), "average.temperature@test.rule"));
        assert (streq (fty_proto_element_src (brecv), "test"));
        assert (streq (fty_proto_state (brecv), "ACTIVE"));
        assert (streq (fty_proto_severity (brecv), "CRITICAL"));
        zsys_debug ("Alert was sent: SUCCESS");
    }
    int ttl2 = fty_proto_aux_number (brecv, "TTL", -1);
    assert (ttl2 != -1);

    zmsg_destroy (&recv);
    zpoller_destroy (&poller);

    // 27.2 update the created asset to something completely different, check that alert is resolved
    // and that we deleted old rules and created new

    zhash_t *aux3 = zhash_new ();
    zhash_autofree (aux3);
    zhash_insert (aux3, "type", (void *) "device");
    zhash_insert (aux3, "subtype", (void *) "epdu");
    m = fty_proto_encode_asset (aux3,
            "test",
            FTY_PROTO_ASSET_OP_UPDATE,
            NULL);
    assert (m);
    rv = mlm_client_send (asset_producer, "device.epdu@test", &m);
    assert ( rv == 0 );

    poller = zpoller_new (mlm_client_msgpipe (consumer), NULL);
    assert (poller);
    which = zpoller_wait (poller, 3*ttl2);
    assert ( which != NULL );
    recv = mlm_client_recv (consumer);
    assert ( recv != NULL );
    assert ( is_fty_proto (recv));
    if ( verbose ) {
        brecv = fty_proto_decode (&recv);
        assert (streq (fty_proto_rule (brecv), "average.temperature@test.rule"));
        assert (streq (fty_proto_element_src (brecv), "test"));
        assert (streq (fty_proto_state (brecv), "RESOLVED"));
        assert (streq (fty_proto_severity (brecv), "CRITICAL"));
        fty_proto_destroy (&brecv);
        zsys_debug ("Alert was sent: SUCCESS");
    }
    int ttl3 = fty_proto_aux_number (brecv, "TTL", -1);
    assert (ttl3 != -1);
    zmsg_destroy (&recv);
    zpoller_destroy (&poller);

    char *average_humidity2 = s_readall ((std::string ("src/testrules") + "/average.humidity@test.rule").c_str ());
    char *average_temperature2 = s_readall ((std::string ("src/testrules") + "/average.temperature@test.rule").c_str ());
    char *realpower_default2 =  s_readall ((std::string ("src/testrules") + "/realpower.default@test.rule").c_str ());
    char *phase_imbalance2 = s_readall ((std::string ("src/testrules") + "/phase.imbalance@test.rule").c_str ());
    assert (average_humidity2 == NULL && average_temperature2 == NULL && realpower_default2 == NULL && phase_imbalance2 == NULL);
    zstr_free (&average_humidity2);
    zstr_free (&average_temperature2);
    zstr_free (&realpower_default2);
    zstr_free (&phase_imbalance2);

    char *load_1phase = s_readall ((std::string ("src/testrules") + "/load.input_1phase@test.rule").c_str ());
    assert (load_1phase);
    char *load_3phase = s_readall ((std::string ("src/testrules") + "/load.input_3phase@test.rule").c_str ());
    assert (load_3phase);
    char *section_load =  s_readall ((std::string ("src/testrules") + "/section_load@test.rule").c_str ());
    assert (section_load);
    char *phase_imbalance3 = s_readall ((std::string ("src/testrules") + "/phase.imbalance@test.rule").c_str ());
    assert (phase_imbalance);
    char *voltage_1phase = s_readall ((std::string ("src/testrules") + "/voltage.input_1phase@test.rule").c_str ());
    assert (voltage_1phase);
    char *voltage_3phase = s_readall ((std::string ("src/testrules") + "/voltage.input_3phase@test.rule").c_str ());
    assert (voltage_3phase);

    zstr_free (&load_1phase);
    zstr_free (&load_3phase);
    zstr_free (&section_load);
    zstr_free (&phase_imbalance3);
    zstr_free (&voltage_1phase);
    zstr_free (&voltage_3phase);

    // force the alert for the updated device

    m = fty_proto_encode_metric (
            NULL, "phase.imbalance", "test", "50", "%", 0);
    assert (m);
    rv = mlm_client_send (producer, "phase.imbalance@test", &m);
    assert ( rv == 0 );

    recv = mlm_client_recv (consumer);
    assert (recv);
    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (brecv);
    int ttl4 = fty_proto_aux_number (brecv, "TTL", -1);
    assert (ttl4 != -1);
    assert (streq (fty_proto_rule (brecv), "phase.imbalance@test.rule"));
    assert (streq (fty_proto_element_src (brecv), "test"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    fty_proto_destroy (&brecv);

    // 28 delete the created asset, check that we deleted the rules and all alerts are resolved

    m = fty_proto_encode_asset (aux3,
            "test",
            FTY_PROTO_ASSET_OP_DELETE,
            NULL);
    assert (m);
    rv = mlm_client_send (asset_producer, "device.epdu@test", &m);
    assert ( rv == 0 );

    load_1phase = s_readall ((std::string ("src/testrules") + "/load.input_1phase@test.rule").c_str ());
    load_3phase = s_readall ((std::string ("src/testrules") + "/load.input_3phase@test.rule").c_str ());
    section_load =  s_readall ((std::string ("src/testrules") + "/section_load@test.rule").c_str ());
    phase_imbalance3 = s_readall ((std::string ("src/testrules") + "/phase.imbalance@test.rule").c_str ());
    voltage_1phase = s_readall ((std::string ("src/testrules") + "/voltage.input_1phase@test.rule").c_str ());
    voltage_3phase = s_readall ((std::string ("src/testrules") + "/voltage.input_3phase@test.rule").c_str ());

    assert (load_1phase == NULL && load_3phase == NULL && section_load == NULL && phase_imbalance3 == NULL && voltage_1phase == NULL && voltage_3phase == NULL);

    zstr_free (&load_1phase);
    zstr_free (&load_3phase);
    zstr_free (&section_load);
    zstr_free (&phase_imbalance3);
    zstr_free (&voltage_1phase);
    zstr_free (&voltage_3phase);

    poller = zpoller_new (mlm_client_msgpipe (consumer), NULL);
    assert (poller);
    which = zpoller_wait (poller, 3*ttl4);
    assert ( which != NULL );
    recv = mlm_client_recv (consumer);
    assert ( recv != NULL );
    assert ( is_fty_proto (recv));
    if ( verbose ) {
        brecv = fty_proto_decode (&recv);
        assert (streq (fty_proto_rule (brecv), "phase.imbalance@test.rule"));
        assert (streq (fty_proto_element_src (brecv), "test"));
        assert (streq (fty_proto_state (brecv), "RESOLVED"));
        assert (streq (fty_proto_severity (brecv), "CRITICAL"));
        fty_proto_destroy (&brecv);
        zsys_debug ("Alert was sent: SUCCESS");
    }
    zmsg_destroy (&recv);
    zpoller_destroy (&poller);

    //  @end
    printf ("OK\n");
}
