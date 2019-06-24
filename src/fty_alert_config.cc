/*  =========================================================================
    fty_alert_config - Actor creating rules for assets

    Copyright (C) 2019 - 2019 Eaton

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
    fty_alert_config - Actor creating rules for assets
@discuss
@end
*/
#include <string>
#include <cxxtools/directory.h>
#include <fstream>

#include "fty_alert_engine_classes.h"

#define MB_DELIVER "MAILBOX DELIVER"

AlertConfig::AlertConfig (const std::string name) : timeout_ (30000), name_(name) {
    client_ = mlm_client_new ();
    assert (client_);
    client_mb_sender_ = mlm_client_new ();
    assert (client_mb_sender_);
    client_mb_sender_poller_ = zpoller_new (mlm_client_msgpipe (client_mb_sender_), NULL);
    timeout_internal_ = 2000;
}

AlertConfig::~AlertConfig () {
    zpoller_destroy (&client_mb_sender_poller_);
    mlm_client_destroy (&client_);
    mlm_client_destroy (&client_mb_sender_);
}

/// handle pipe messages for this actor
int AlertConfig::handlePipeMessages (zsock_t *pipe) {
    log_debug ("Handling pipe messages");
    zmsg_t *msg = zmsg_recv (pipe);
    char *cmd = zmsg_popstr (msg);
    log_debug ("Command : %s", cmd);

    if (streq (cmd, "$TERM")) {
        log_debug ("$TERM received");
        zstr_free (&cmd);
        zmsg_destroy (&msg);
        return 1;
    }
    else
    if (streq (cmd, "CONNECT")) {
        log_debug ("CONNECT received");
        char* endpoint = zmsg_popstr (msg);
        int rv = mlm_client_connect (client_, endpoint, 1000, name_.c_str ());
        if (rv == -1)
            log_error ("%s: can't connect to malamute endpoint '%s'", name_.c_str (), endpoint);
        std::string client_mb_sender_name = std::string ("client_mb_sender") + std::to_string (random ()) + "." +
            std::to_string (getpid ());
        rv = mlm_client_connect (client_mb_sender_, endpoint, 1000, client_mb_sender_name.c_str ());
        if (rv == -1)
            log_error ("%s: can't connect to malamute endpoint '%s'", client_mb_sender_name.c_str (), endpoint);
        zstr_free (&endpoint);
    }
    else
    if (streq (cmd, "TIMEOUT")) {
        log_debug ("TIMEOUT received");
        char* timeout = zmsg_popstr (msg);
        timeout_ = std::stoull (timeout);
        zstr_free (&timeout);
    }
    else
    if (streq (cmd, "TIMEOUT_INTERNAL")) {
        log_debug ("TIMEOUT_INTERNAL received");
        char* timeout = zmsg_popstr (msg);
        timeout_internal_ = std::stoull (timeout);
        zstr_free (&timeout);
    }
    else
    if (streq (cmd, "ALERT_TRIGGER_MB_NAME")) {
        log_debug ("ALERT_TRIGGER_MB_NAME received");
        char* name = zmsg_popstr (msg);
        alert_trigger_mb_name_ = name;
        zstr_free (&name);
    }
    else
    if (streq (cmd, "CONSUMER")) {
        log_debug ("CONSUMER received");
        char* stream = zmsg_popstr (msg);
        char* pattern = zmsg_popstr (msg);
        int rv = mlm_client_set_consumer (client_, stream, pattern);
        if (rv == -1)
            log_error ("can't set consumer on stream '%s', '%s'", stream, pattern);
        zstr_free (&pattern);
        zstr_free (&stream);
    }
    else
    if (streq (cmd, "TEMPLATES_DIR")) {
        log_debug ("TEMPLATES_DIR received");
        char* filename = zmsg_popstr (msg);
        if (filename) {
            template_location_ = filename;
        } else {
            log_error ("in CONFIG command next frame is missing");
        }
        zstr_free (&filename);
    }
    zstr_free (&cmd);
    zmsg_destroy (&msg);
    return 0;
}

std::map<std::string, std::shared_ptr<Rule>> AlertConfig::getAllTemplatesMap () {
    log_debug ("Getting all templates");
    std::map<std::string, std::shared_ptr<Rule>> result;
    if (!cxxtools::Directory::exists (template_location_)) {
        log_info ("TemplateRuleConfigurator '%s' dir does not exist", template_location_.c_str ());
        return result;
    }
    cxxtools::Directory directory (template_location_);
    for ( const auto &filename : directory) {
        if ( filename.compare (".")!=0  && filename.compare ("..")!=0) {
            // read the template rule from the file
            std::ifstream file (directory.path () + "/" + filename);
            std::string file_content ((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
            try {
                std::shared_ptr<Rule> rule = RuleFactory::createFromJson (file_content);
                result[filename] = rule;
            } catch (std::exception &e) {
                log_warning ("Unable to load file %s/%s", directory.path ().c_str (), filename.c_str ());
            }
        }
    }
    return result;
}

std::string AlertConfig::convertTypeSubType2Name (const char *type, const char *subtype) {
    std::string name;
    std::string prefix ("__");
    std::string subtype_str (subtype);
    if (subtype_str.empty () || (subtype_str == "unknown") || (subtype_str == "N_A"))
        name = prefix + type + prefix;
    else
        name = prefix + type + '_' + subtype + prefix;
    return name;
}

bool AlertConfig::ruleMatchAsset (const std::pair<std::string, std::shared_ptr<Rule>> &rule_template,
        FullAssetSPtr asset) {
    log_debug ("Check if rule match asset");
    std::string type_subtype = convertTypeSubType2Name (asset->getTypeString ().c_str (),
            asset->getSubtypeString ().c_str ());
    if (rule_template.first.find (type_subtype) != std::string::npos)
        return true;
    return false;
}

std::vector<FullAssetSPtr> AlertConfig::getMatchingAssets (std::pair<const std::string,
        std::shared_ptr<Rule>> &rule_template) {
    log_debug ("Get assets matching rule");
    std::vector<FullAssetSPtr> result;
    for (auto &asset_iterator : FullAssetDatabase::getInstance ()) {
        if (ruleMatchAsset (rule_template, asset_iterator.second)) {
            result.push_back (asset_iterator.second);
        }
    }
    return result;
}

void AlertConfig::listTemplates (std::string corr_id, std::string type) {
    log_debug ("Listing template");
    std::function<bool (const std::string & s) > filter_class, filter_type;
    if (type.empty ())
        type = "all";
    if (type == "all") {
        filter_type = [](const std::string & s) {
            return true;
        };
    } else if (type == "threshold") {
        filter_type = [](const std::string & s) {
            return s.compare ("threshold") == 0;
        };
    } else if (type == "single") {
        filter_type = [](const std::string & s) {
            return s.compare ("single") == 0;
        };
    } else if (type == "pattern") {
        filter_type = [](const std::string & s) {
            return s.compare ("pattern") == 0;
        };
    } else {
        //invalid type
        log_warning ("type '%s' is invalid", type.c_str ());
        zmsg_t *reply = zmsg_new ();
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "INVALID_TYPE");
        mlm_client_sendto (client_, mlm_client_sender (client_), RULES_SUBJECT,
                mlm_client_tracker (client_), 1000, &reply);
        return;
    }
    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "LIST");
    zmsg_addstr (reply, corr_id.c_str ());
    zmsg_addstr (reply, type.c_str ());
    for (auto &template_pair : getAllTemplatesMap ()) {
        if (filter_type (template_pair.second->whoami ())) {
            zmsg_addstr (reply, template_pair.first.c_str ());
            zmsg_addstr (reply, template_pair.second->getJsonRule ().c_str ());
            std::vector<FullAssetSPtr> matching_assets = getMatchingAssets (template_pair);
            std::string asset_list;
            for (size_t i = 0; i < matching_assets.size (); ++i) {
                if (i > 0)
                    asset_list.append (",");
                asset_list.append (matching_assets[i]->getId ());
            }
            zmsg_addstr (reply, asset_list.c_str ());
        }
    }
    mlm_client_sendto (client_, mlm_client_sender (client_), RULES_SUBJECT, mlm_client_tracker (client_), 1000, &reply);
}

/// handle mailbox messages
void AlertConfig::handleMailboxMessages (zmsg_t **msg) {
    log_debug ("Handling mailbox messages");
    zmsg_t *zmessage = *msg;
    if (zmessage == NULL) {
        return;
    }
    if (streq (mlm_client_subject (client_), RULES_SUBJECT)) {
        char *command = zmsg_popstr (zmessage);
        char *corr_id = zmsg_popstr (zmessage);
        char *param = zmsg_popstr (zmessage);
        log_debug ("Incoming message: subject: '%s', command: '%s', param: '%s'", RULES_SUBJECT, command, param);
        if (command != nullptr) {
            if (streq (command, "LIST")) {
                listTemplates (corr_id, param == nullptr ? "" : param);
            }
            /*
             * fty-nut and others might want to pass rules to alert system, this should be entry point
            else if (streq (command, "ADD")) {
                if ( zmsg_size (zmessage) == 0 ) {
                    // ADD/json
                    addTemplate (param);
                }
                else {
                    // ADD/json/old_name
                    char *param1 = zmsg_popstr (zmessage);
                    updateTemplate (param, param1);
                    if (param1) free (param1);
                }
            }
            */
            else {
                log_error ("Received unexpected message to MAILBOX with command '%s'", command);
            }
        }
        zstr_free (&command);
        zstr_free (&corr_id);
        zstr_free (&param);
    } else {
        char *command = zmsg_popstr (zmessage);
        log_error ("%s: Unexpected mailbox message received with command : %s", name_.c_str (), command);
        zstr_free (&command);
    }
    if (zmessage) {
        zmsg_destroy (&zmessage);
    }
}

/// handle mailbox messages
void AlertConfig::handleStreamMessages (zmsg_t **msg) {
    log_debug ("Handling stream messages");
    zmsg_t *zmsg = *msg;
    std::string topic = mlm_client_subject (client_);
    if (!is_fty_proto (zmsg)) {
        zmsg_destroy (&zmsg);
        return;
    }
    fty_proto_t *bmessage = fty_proto_decode (&zmsg);
    if (fty_proto_id (bmessage) != FTY_PROTO_ASSET) {
        fty_proto_destroy (&bmessage);
        return;
    }
    const char *operation = fty_proto_operation (bmessage);
    if (streq (operation, FTY_PROTO_ASSET_OP_UPDATE)) {
        FullAssetSPtr assetptr = getFullAssetFromFtyProto (bmessage);
        FullAssetDatabase::getInstance ().insertOrUpdateAsset (assetptr);
    } else if (streq (operation, FTY_PROTO_ASSET_OP_DELETE)) {
        const char *assetname = fty_proto_name (bmessage);
        FullAssetDatabase::getInstance ().deleteAsset (assetname);
    }
    fty_proto_destroy (&bmessage);
}

void AlertConfig::onAssetCreateCallback (FullAssetSPtr assetptr) {
    log_debug ("on asset create callback");
    std::map<std::string, std::shared_ptr<Rule>> rules = getAllTemplatesMap ();
    for (auto &rule_it : rules) {
        if (ruleMatchAsset (rule_it, assetptr)) {
            auto name_it = rule_it.second->getName ().find ("__name__");
            rule_it.second->setName (rule_it.second->getName ().replace (name_it, name_it+std::strlen ("__name__"),
                assetptr->getId ()));
            zmsg_t *message = zmsg_new ();
            zmsg_addstr (message, "ADD");
            zmsg_addstr (message, name_.c_str ()); // uuid, no need to generate it
            zmsg_addstr (message, rule_it.second->getJsonRule ().c_str ());
            mlm_client_sendto (client_mb_sender_, alert_trigger_mb_name_.c_str (), RULES_SUBJECT,
                    mlm_client_tracker (client_), 1000, &message);
            // expect response
            void *which = zpoller_wait (client_mb_sender_poller_, timeout_internal_);
            if (which != nullptr) {
                message = mlm_client_recv (client_mb_sender_);
                assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mb_sender_));
                char *command = zmsg_popstr (message);
                if (!streq (command, "OK")) {
                    char *corr_id = zmsg_popstr (message);
                    char *param = zmsg_popstr (message);
                    log_error ("%s refused rule %s", alert_trigger_mb_name_.c_str (),
                        rule_it.second->getJsonRule ().c_str ());
                    zstr_free (&corr_id);
                    zstr_free (&param);
                }
                zstr_free (&command);
                zmsg_destroy (&message);
            }
        }
    }
}
void AlertConfig::onAssetDeleteCallback (FullAssetSPtr assetptr) {
    log_debug ("on asset delete callback");
    zmsg_t *message = zmsg_new ();
    zmsg_addstr (message, "DELETE_ELEMENT");
    zmsg_addstr (message, name_.c_str ()); // uuid, no need to generate it
    zmsg_addstr (message, assetptr->getId ().c_str ());
    mlm_client_sendto (client_mb_sender_, alert_trigger_mb_name_.c_str (), RULES_SUBJECT, mlm_client_tracker (client_),
            1000, &message);
    // expect response
    void *which = zpoller_wait (client_mb_sender_poller_, timeout_internal_);
    if (which != nullptr) {
        message = mlm_client_recv (client_mb_sender_);
        assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mb_sender_));
        char *command = zmsg_popstr (message);
        if (!streq (command, "OK")) {
            char *corr_id = zmsg_popstr (message);
            char *param = zmsg_popstr (message);
            log_error ("%s refused to delete rules for asset %s", alert_trigger_mb_name_.c_str (),
                assetptr->getId ().c_str ());
            zstr_free (&corr_id);
            zstr_free (&param);
        }
        zstr_free (&command);
        zmsg_destroy (&message);
    }
}

void AlertConfig::run (zsock_t *pipe) {
    log_debug ("Running agent");
    FullAssetDatabase::getInstance ().setOnCreate (std::bind (&AlertConfig::onAssetCreateCallback, this,
            std::placeholders::_1));
    /*
     * updates are not tracked for rule purposes
    FullAssetDatabase::getInstance ().setOnUpdate (std::bind (&AlertConfig::onAssetUpdateCallback, this,
            std::placeholders::_1));
    FullAssetDatabase::getInstance ().setOnUpdateOnlyOnDifference (true);
    */
    FullAssetDatabase::getInstance ().setOnDelete (std::bind (&AlertConfig::onAssetDeleteCallback, this,
            std::placeholders::_1));

    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (client_), mlm_client_msgpipe (client_mb_sender_), NULL);
    assert (poller);

    zsock_signal (pipe, 0);
    log_info ("Actor %s started",name_.c_str ());
    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, timeout_);
        if (which == mlm_client_msgpipe (client_mb_sender_)){
            zmsg_t *zmsg = mlm_client_recv (client_mb_sender_);
            zmsg_destroy (&zmsg);
        }
        // handle termination
        if (which == NULL) {
            if (zpoller_terminated (poller) || zsys_interrupted) {
                log_warning ("%s: zpoller_terminated () or zsys_interrupted. Shutting down.", name_.c_str ());
                break;
            }
            continue;
        }
        // handle messages
        if (which == pipe) {
            if (handlePipeMessages (pipe) == 0) {
                continue;
            } else {
                break;
            }
        } else {
            zmsg_t *zmsg = mlm_client_recv (client_);
            if (streq (MB_DELIVER, mlm_client_command (client_))) {
                handleMailboxMessages (&zmsg);
            } else {
                handleStreamMessages (&zmsg);
            }
        }
    }
    zpoller_destroy (&poller);
}

void fty_alert_config_main (zsock_t *pipe, void* args) {
    log_debug ("starting agent");
    char *name = (char*) args;
    AlertConfig ac (name);
    ac.run (pipe);
}

//  --------------------------------------------------------------------------
//  Self test of this class

// If your selftest reads SCMed fixture data, please keep it in
// src/selftest-ro; if your test creates filesystem objects, please
// do so under src/selftest-rw.
// The following pattern is suggested for C selftest code:
//    char *filename = NULL;
//    filename = zsys_sprintf ("%s/%s", SELFTEST_DIR_RO, "mytemplate.file");
//    assert (filename);
//    ... use the "filename" for I/O ...
//    zstr_free (&filename);
// This way the same "filename" variable can be reused for many subtests.
#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

void
fty_alert_config_test (bool verbose)
{
    printf (" * fty_alert_config: ");

    log_debug ("Test 0: initialization");
    // create stream producer for assets
    mlm_client_t *client_assets = mlm_client_new ();
    int rv = mlm_client_connect (client_assets, "inproc://@/malamute", 1000, "fty_alert_config_test_assets_producer");
    assert (rv == 0);
    rv = mlm_client_set_producer (client_assets, "fty_alert_config_test_assets_stream");
    assert (rv == 0);
    // create agent for mailboxes
    mlm_client_t *client_mailbox = mlm_client_new ();
    rv = mlm_client_connect (client_mailbox, "inproc://@/malamute", 1000, "fty_alert_config_test_trigger");
    assert (rv == 0);
    // poller
    zpoller_t *poller = zpoller_new (mlm_client_msgpipe (client_assets), mlm_client_msgpipe (client_mailbox), NULL);
    assert (poller);

    zactor_t *agent_config = zactor_new (fty_alert_config_main, (void*) "fty_alert_config_test");
    sleep (1);
    // set everything up
    zstr_sendx (agent_config, "CONNECT", "inproc://@/malamute", NULL);
    zstr_sendx (agent_config, "TIMEOUT", "30000", NULL);
    zstr_sendx (agent_config, "TIMEOUT_INTERNAL", "3000000", NULL);
    zstr_sendx (agent_config, "TEMPLATES_DIR", SELFTEST_DIR_RO "/templates", NULL); // rule template
    zstr_sendx (agent_config, "CONSUMER", "fty_alert_config_test_assets_stream", ".*", NULL);
    zstr_sendx (agent_config, "ALERT_TRIGGER_MB_NAME", "fty_alert_config_test_trigger", NULL); // trigger mailbox name
    sleep (1);

    log_debug ("Test 1: send asset datacenter, expected rule average.temperature@dc-1");
    // send asset - DC
    // expected: rule average.temperature@dc-1
    zhash_t *asset_aux = zhash_new ();
    zhash_autofree (asset_aux);
    zhash_insert (asset_aux, "type", (void *) "datacenter");
    zhash_insert (asset_aux, "subtype", (void *) "n_a");
    zhash_t *asset_ext = zhash_new ();
    zhash_autofree (asset_ext);
    zhash_insert (asset_ext, "name", (void *) "DC-Roztoky");
    zmsg_t *asset = fty_proto_encode_asset (asset_aux, "datacenter-1", FTY_PROTO_ASSET_OP_UPDATE, asset_ext);
    rv = mlm_client_send (client_assets, "CREATE", &asset);
    assert (rv == 0);
    zhash_destroy (&asset_ext);
    zhash_destroy (&asset_aux);
    // this should produce a message with rule datacenter
    int counter = 0;
    while (counter < 20) {
        void *which = zpoller_wait (poller, 10000);
        if (which == mlm_client_msgpipe (client_assets)) {
            assert (false); // unexpected message to this client
        } else if (which == mlm_client_msgpipe (client_mailbox)) {
            zmsg_t *zmessage = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (zmessage);
            char *corr_id = zmsg_popstr (zmessage);
            char *param = zmsg_popstr (zmessage);
            assert (std::string ("ADD") == command);
            assert (!std::string (param).empty ());
            auto rule_ptr = RuleFactory::createFromJson (param);
            assert (rule_ptr->getName () == "average.temperature@datacenter-1");
            // proper reply
            mlm_client_sendtox (client_mailbox, mlm_client_sender (client_mailbox), RULES_SUBJECT, "OK", corr_id,
                    nullptr);
            zstr_free (&command);
            zstr_free (&corr_id);
            zstr_free (&param);
            zmsg_destroy (&zmessage);
            break;
        } else {
            ++counter;
        }
    }
    assert (counter < 20);

    log_debug ("Test 2: send asset ups, expected no rules");
    // send asset - device ups
    // expected: empty result
    asset_aux = zhash_new ();
    zhash_autofree (asset_aux);
    zhash_insert (asset_aux, "type", (void *) "device");
    zhash_insert (asset_aux, "subtype", (void *) "ups");
    asset_ext = zhash_new ();
    zhash_autofree (asset_ext);
    zhash_insert (asset_ext, "name", (void *) "MyUPS");
    asset = fty_proto_encode_asset (asset_aux, "ups-22", FTY_PROTO_ASSET_OP_UPDATE, asset_ext);
    rv = mlm_client_send (client_assets, "CREATE", &asset);
    assert (rv == 0);
    zhash_destroy (&asset_ext);
    zhash_destroy (&asset_aux);
    // this should produce a message with rule datacenter
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_assets)) {
            assert (false); // unexpected message to this client
        }
        if (which == mlm_client_msgpipe (client_mailbox)) {
            assert (false); // there are no test rules for ups, so no message should come
        }
    }
    assert (counter >= 20);

    log_debug ("Test 3: send asset rack, expected 4 rules");
    // send asset - device rack
    // expected: 4 rules: average.humidity@__rack__.rule, average.temperature@__rack__.rule,
    //                    phase_imbalance@__rack__.rule, realpower.default_1phase@__rack__.rule
    asset_aux = zhash_new ();
    zhash_autofree (asset_aux);
    zhash_insert (asset_aux, "type", (void *) "rack");
    zhash_insert (asset_aux, "subtype", (void *) "n_a");
    asset_ext = zhash_new ();
    zhash_autofree (asset_ext);
    zhash_insert (asset_ext, "name", (void *) "Rack 1");
    asset = fty_proto_encode_asset (asset_aux, "rack-3", FTY_PROTO_ASSET_OP_UPDATE, asset_ext);
    rv = mlm_client_send (client_assets, "CREATE", &asset);
    assert (rv == 0);
    zhash_destroy (&asset_ext);
    zhash_destroy (&asset_aux);
    // this should produce a message with rule datacenter
    counter = 0;
    int rules_count = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 10000);
        if (which == mlm_client_msgpipe (client_assets)) {
            assert (false); // unexpected message to this client
        }
        if (which == mlm_client_msgpipe (client_mailbox)) {
            zmsg_t *zmessage = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (zmessage);
            char *corr_id = zmsg_popstr (zmessage);
            char *param = zmsg_popstr (zmessage);
            assert (std::string ("ADD") == command);
            assert (!std::string (param).empty ());
            auto rule_ptr = RuleFactory::createFromJson (param);
            assert (rule_ptr->getName () == "average.humidity-input@rack-3" ||
                rule_ptr->getName () == "average.temperature-input@rack-3" ||
                rule_ptr->getName () == "phase_imbalance@rack-3" ||
                rule_ptr->getName () == "realpower.default@rack-3");
            // proper reply
            mlm_client_sendtox (client_mailbox, mlm_client_sender (client_mailbox), RULES_SUBJECT, "OK", corr_id,
                    nullptr);
            zstr_free (&command);
            zstr_free (&corr_id);
            zstr_free (&param);
            zmsg_destroy (&zmessage);
            if (++rules_count == 4)
                break;
        }
    }
    assert (counter < 20);
    assert (rules_count == 4);

    log_debug ("Test 4: list rules");
    // send mailbox list, check response
    zmsg_t *message = zmsg_new ();
    zmsg_addstr (message, "LIST");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    mlm_client_sendto (client_mailbox, "fty_alert_config_test", RULES_SUBJECT, mlm_client_tracker (client_mailbox),
        1000, &message);
    counter = 0;
    rules_count = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 10000);
        if (which == mlm_client_msgpipe (client_assets)) {
            assert (false); // unexpected message to this client
        }
        if (which == mlm_client_msgpipe (client_mailbox)) {
            zmsg_t *zmessage = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (zmessage);
            char *corr_id = zmsg_popstr (zmessage);
            char *param = zmsg_popstr (zmessage);
            assert (streq ("LIST", command));
            assert (streq ("uuidtest", corr_id));
            assert (streq ("all", param));
            for (;;) {
                char *filename = zmsg_popstr (zmessage);
                if (filename == nullptr)
                    break;
                char *rulejson = zmsg_popstr (zmessage);
                assert (rulejson != nullptr);
                char *assets = zmsg_popstr (zmessage);
                assert (assets!= nullptr);
                // TODO: FIXME: add more complex tests to check content
                ++rules_count;
                zstr_free (&filename);
                zstr_free (&rulejson);
                zstr_free (&assets);
            }
            zstr_free (&command);
            zstr_free (&corr_id);
            zstr_free (&param);
            zmsg_destroy (&zmessage);
            break;
        }
    }
    assert (counter < 20);
    assert (rules_count == 5);

    log_debug ("Test 5: send asset ups delete");
    // send asset - device ups
    // expected: empty result
    asset_aux = zhash_new ();
    zhash_autofree (asset_aux);
    zhash_insert (asset_aux, "type", (void *) "device");
    zhash_insert (asset_aux, "subtype", (void *) "ups");
    asset_ext = zhash_new ();
    zhash_autofree (asset_ext);
    zhash_insert (asset_ext, "name", (void *) "MyUPS");
    asset = fty_proto_encode_asset (asset_aux, "ups-22", FTY_PROTO_ASSET_OP_DELETE, asset_ext);
    rv = mlm_client_send (client_assets, "DELETE", &asset);
    assert (rv == 0);
    zhash_destroy (&asset_ext);
    zhash_destroy (&asset_aux);
    // this should produce a message with rule datacenter
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 10000);
        if (which == mlm_client_msgpipe (client_assets)) {
            assert (false); // unexpected message to this client
        }
        if (which == mlm_client_msgpipe (client_mailbox)) {
            zmsg_t *zmessage = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (zmessage);
            char *corr_id = zmsg_popstr (zmessage);
            char *param = zmsg_popstr (zmessage);
            assert (std::string ("DELETE_ELEMENT") == command);
            assert (std::string (param) == "ups-22");
            // proper reply
            mlm_client_sendtox (client_mailbox, mlm_client_sender (client_mailbox), RULES_SUBJECT, "OK", corr_id,
                    nullptr);
            zstr_free (&command);
            zstr_free (&corr_id);
            zstr_free (&param);
            zmsg_destroy (&zmessage);
            break;
        }
    }
    assert (counter <= 20);

    log_debug ("Test 6 no messages in queue");
    while (counter < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which != nullptr)
            assert (false);
        ++counter;
    }
    assert (counter >= 20);

    zpoller_destroy (&poller);
    mlm_client_destroy (&client_assets);
    mlm_client_destroy (&client_mailbox);
    zactor_destroy (&agent_config);

    printf ("OK\n");
}
