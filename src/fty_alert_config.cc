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

const std::string AlertConfig::MB_DELIVER = "MAILBOX DELIVER";

AlertConfig::AlertConfig (const std::string name) : timeout_ (30000), name_(name) {
    client_ = mlm_client_new ();
    assert (client_);
}

AlertConfig::~AlertConfig () {
    mlm_client_destroy (&client_);
}

/// handle pipe messages for this actor
int AlertConfig::handlePipeMessages (zsock_t *pipe) {
    zmsg_t *msg = zmsg_recv (pipe);
    char *cmd = zmsg_popstr (msg);
    log_debug ("Command : %s", cmd);

    if (streq (cmd, "$TERM")) {
        log_debug ("%s: $TERM received", name_.c_str ());
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
            log_error ("%s: can't set consumer on stream '%s', '%s'", name_.c_str (), stream, pattern);
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
            log_error ("%s: in CONFIG command next frame is missing", name_.c_str ());
        }
        zstr_free (&filename);
    }
    zstr_free (&cmd);
    zmsg_destroy (&msg);
    return 0;
}

std::map<std::string, std::shared_ptr<Rule>> AlertConfig::getAllTemplatesMap () {
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

bool AlertConfig::ruleMatchAsset (const std::pair<std::string, std::shared_ptr<Rule>> &rule_template, FullAssetSPtr asset) {
    std::string type_subtype = convertTypeSubType2Name (asset->getTypeString ().c_str (), asset->getSubtypeString ().c_str ());
    if (rule_template.first.find (type_subtype) != std::string::npos)
        return true;
    return false;
}

std::vector<FullAssetSPtr> AlertConfig::getMatchingAssets (std::pair<const std::string, std::shared_ptr<Rule>> &rule_template) {
    std::vector<FullAssetSPtr> result;
    for (auto &asset_iterator : FullAssetDatabase::getInstance ()) {
        if (ruleMatchAsset (rule_template, asset_iterator.second)) {
            result.push_back (asset_iterator.second);
        }
    }
    return result;
}

void AlertConfig::listTemplates (std::string corr_id, std::string type) {
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
        }
    }
    mlm_client_sendto (client_, mlm_client_sender (client_), RULES_SUBJECT, mlm_client_tracker (client_), 1000, &reply);
}

/// handle mailbox messages
void AlertConfig::handleMailboxMessages () {
    zmsg_t *zmessage = mlm_client_recv (client_);
    if (zmessage == NULL) {
        return;
    }
    if (streq (mlm_client_subject (client_), RULES_SUBJECT)) {
        char *command = zmsg_popstr (zmessage);
        char *corr_id = zmsg_popstr (zmessage);
        char *param = zmsg_popstr (zmessage);
        log_debug ("Incoming message: subject: '%s', command: '%s', param: '%s'", RULES_SUBJECT, command, param);
        if (command != nullptr && param != nullptr) {
            if (streq (command, "LIST")) {
                listTemplates (corr_id, param);
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
void AlertConfig::handleStreamMessages () {
    zmsg_t *zmsg = mlm_client_recv (client_);
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
    std::map<std::string, std::shared_ptr<Rule>> rules = getAllTemplatesMap ();
    for (auto &rule_it : rules) {
        if (ruleMatchAsset (rule_it, assetptr)) {
            zmsg_t *reply = zmsg_new ();
            zmsg_addstr (reply, "ADD");
            zmsg_addstr (reply, rule_it.second->getJsonRule ().c_str ());
            mlm_client_sendto (client_, alert_trigger_mb_name_.c_str (), RULES_SUBJECT, mlm_client_tracker (client_), 1000, &reply);
        }
    }
}
void AlertConfig::onAssetDeleteCallback (FullAssetSPtr assetptr) {
    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "DELETE_ELEMENT");
    zmsg_addstr (reply, assetptr->getId ().c_str ());
    mlm_client_sendto (client_, alert_trigger_mb_name_.c_str (), RULES_SUBJECT, mlm_client_tracker (client_), 1000, &reply);
}

void AlertConfig::run (zsock_t *pipe) {
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

    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (client_), NULL);
    assert (poller);

    zsock_signal (pipe, 0);
    log_info ("Actor %s started",name_.c_str ());
    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, timeout_);
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
        } else if (MB_DELIVER == mlm_client_command (client_)) {
            handleMailboxMessages ();
        } else {
            handleStreamMessages ();
        }
    }
    zpoller_destroy (&poller);
}

void fty_alert_config_main (zsock_t *pipe, void* args) {
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

    //  @selftest
    //  Simple create/destroy test
    //  @end
    printf ("OK\n");
}
