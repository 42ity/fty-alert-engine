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
#include <regex>

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
    FullAssetDatabase::getInstance ().clear ();
}

zmsg_t *AlertConfig::sendRule (const std::shared_ptr<Rule> rule, const std::string &rule_old_name) {
    zmsg_t *message = zmsg_new ();
    zmsg_addstr (message, name_.c_str ()); // uuid, no need to generate it
    zmsg_addstr (message, "ADD");
    zmsg_addstr (message, rule->getJsonRule ().c_str ());
    if (!rule_old_name.empty ())
        zmsg_addstr (message, rule_old_name.c_str ());
    mlm_client_sendto (client_mb_sender_, alert_trigger_mb_name_.c_str (), RULES_SUBJECT, mlm_client_tracker (client_),
            1000, &message);
            // expect response
    void *which = zpoller_wait (client_mb_sender_poller_, timeout_internal_);
    if (which != nullptr) {
        message = mlm_client_recv (client_mb_sender_);
        char *corr_id = zmsg_popstr (message);
        if (name_ == corr_id) {
            zstr_free (&corr_id);
            return message;
        } else {
            return nullptr;
        }
    }
    return nullptr;
}

void AlertConfig::loadAndSendRule (const std::string rulename) {
    log_debug ("loadAndSendRule %s", rulename.c_str ());
    std::ifstream file (template_location_ + "/" + rulename);
    std::string file_content ((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    try {
        std::shared_ptr<Rule> rule = RuleFactory::createFromJson (file_content);
        zmsg_t *message = AlertConfig::sendRule (rule, std::string ());
        if (message != nullptr) {
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mb_sender_));
            char *command = zmsg_popstr (message);
            if (!streq (command, "OK")) {
                char *param = zmsg_popstr (message);
                if (streq (param, "ALREADY_EXISTS")) {
                    log_debug ("Rule %s already known", rule->getName ().c_str ());
                } else {
                    log_error ("%s refused rule %s due to %s", alert_trigger_mb_name_.c_str (),
                            rule->getJsonRule ().c_str (), param);
                }
                zstr_free (&param);
            }
            zstr_free (&command);
            zmsg_destroy (&message);
        } else {
            log_error ("No reply received from %s on ADD rule %s", alert_trigger_mb_name_.c_str (), rulename.c_str ());
        }
    } catch (std::runtime_error &re) {
        log_error ("Exception %s caught while trying to send rule %s", re.what (), rulename.c_str ());
    } catch (...) {
        log_error ("Undefined exception caught while trying to send rule %s", rulename.c_str ());
    }
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
    else
    if (streq (cmd, "SEND_RULE")) {
        log_debug ("SEND_RULE received");
        char* rulename = zmsg_popstr (msg);
        if (rulename) {
            loadAndSendRule (rulename);
        } else {
            log_error ("missing rulename");
        }
        zstr_free (&rulename);
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
    for (const auto &filename : directory) {
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

std::string AlertConfig::convertTypeSubType2Name (const std::string &type, const std::string &subtype) {
    std::string name;
    std::string prefix ("__");
    if (subtype.empty () || (subtype == "unknown") || (subtype == "N_A"))
        name = prefix + type + "_n_a" + prefix;
    else
        name = prefix + type + '_' + subtype + prefix;
    return name;
}

bool AlertConfig::ruleMatchAsset (const std::pair<std::string, std::shared_ptr<Rule>> &rule_template,
        FullAssetSPtr asset) {
    log_debug ("Check if rule match asset");
    std::string type_subtype = convertTypeSubType2Name (asset->getTypeString (), asset->getSubtypeString ());
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

void AlertConfig::listTemplates (std::string corr_id, zmsg_t *msg) {
    log_debug ("Listing template");
    char *param = zmsg_popstr (msg);
    std::string type (param == nullptr ? "all" : param);
    zstr_free (&param);
    std::function<bool (const std::string & s) > filter;
    if (type.empty ())
        type = "all";
    if (type == "all") {
        filter = [](const std::string & s) {
            return true;
        };
    } else {
        // TODO: FIXME: add proper filtering system like key value filter rather than regex on json representation
        log_debug ("Filtering out in function for %s", type.c_str ());
        filter = [&](std::string s) {
            std::regex r (type);
            s.erase (remove_if (s.begin (), s.end (), isspace), s.end ());
            if (std::regex_search (s, r)) {
                return true;
            } else {
                return false;
            }
        };
    }
    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, corr_id.c_str ());
    zmsg_addstr (reply, "LIST");
    zmsg_addstr (reply, type.c_str ());
    for (auto &template_pair : getAllTemplatesMap ()) {
        if (filter (template_pair.second->getJsonRule ())) {
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

// simply validate rule and pass it to trigger
void AlertConfig::passRule (std::string corr_id, zmsg_t *msg, std::string sender) {
    log_debug ("Passing rule");
    char *param1 = zmsg_popstr (msg);
    std::string json (param1 == nullptr ? "" : param1);
    zstr_free (&param1);
    char *param2 = zmsg_popstr (msg);
    std::string old_name (param2 == nullptr ? "" : param2);
    zstr_free (&param2);
    zmsg_t *reply = zmsg_new ();
    try {
        std::shared_ptr<Rule> rule_ptr = RuleFactory::createFromJson (json);
        if (rule_ptr->getSource ().empty ())
            rule_ptr->setSource (sender);
        zmsg_t *message = AlertConfig::sendRule (rule_ptr, old_name);
        if (message != nullptr) {
            // pass content of message to reply
            zmsg_addstr (reply, corr_id.c_str ());
            char *str = zmsg_popstr (message);
            while (str != nullptr) {
                zmsg_addstr (reply, str);
                zstr_free (&str);
            }
        } else {
            throw std::logic_error ("no response");
        }
    } catch (lua_exception &le) {
        log_debug ("rule lua exception caught: %s", le.what ());
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_LUA");
    } catch (cxxtools::SerializationError &se) {
        log_warning ("bad json for rule %s", json.c_str ());
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_JSON");
    } catch (std::exception &e) {
        log_debug ("rule exception caught: %s", e.what ());
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "Internal error");
    } catch (...) {
        log_debug ("Unidentified rule exception caught!");
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "Internal error");
    }
    mlm_client_sendto (client_, mlm_client_sender (client_), RULES_SUBJECT, mlm_client_tracker (client_), 1000, &reply);
}

// validate template, store it and try matching it to existing assets
void AlertConfig::addTemplate (std::string corr_id, zmsg_t *msg, std::string sender) {
    log_debug ("Adding template");
    char *param1 = zmsg_popstr (msg);
    std::string json (param1 == nullptr ? "" : param1);
    zstr_free (&param1);
    char *param2 = zmsg_popstr (msg);
    std::string old_name (param2 == nullptr ? "" : param2);
    zstr_free (&param2);
    zmsg_t *reply = zmsg_new ();
    try {
        std::shared_ptr<Rule> rule_ptr = RuleFactory::createFromJson (json);
        if (rule_ptr->getSource ().empty ())
            rule_ptr->setSource (sender);
        rule_ptr->save (template_location_);
        std::pair<const std::string, std::shared_ptr<Rule>> rule_pair (rule_ptr->getName (), rule_ptr);
        auto vector_of_assets = getMatchingAssets (rule_pair);
        for (auto one_asset : vector_of_assets) {
            sendRuleForAsset (one_asset, rule_ptr, rule_ptr->getName ());
        }
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "OK");
    } catch (lua_exception &le) {
        log_debug ("rule lua exception caught: %s", le.what ());
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_LUA");
    } catch (unable_to_save &uts) {
        log_debug ("rule exists exception caught: %s", uts.what ());
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "Internal error - operating with storage/disk failed.");
    } catch (cxxtools::SerializationError &se) {
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_JSON");
    } catch (std::exception &e) {
        log_debug ("rule exception caught: %s", e.what ());
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "Internal error");
    } catch (...) {
        log_debug ("Unidentified rule exception caught!");
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "Internal error");
    }
    mlm_client_sendto (client_, mlm_client_sender (client_), RULES_SUBJECT, mlm_client_tracker (client_), 1000, &reply);
}

// get one template
void AlertConfig::getTemplate (std::string corr_id, zmsg_t *msg) {
    log_debug ("Gettting template");
    char *param1 = zmsg_popstr (msg);
    std::string rulename (param1 == nullptr ? "" : param1);
    zstr_free (&param1);
    std::ifstream file (template_location_ + "/" + rulename + ".rule");
    std::string file_content ((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    zmsg_t *reply = zmsg_new ();
    try {
        std::shared_ptr<Rule> rule = RuleFactory::createFromJson (file_content);
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "OK");
        zmsg_addstr (reply, rule->getJsonRule ().c_str ());
    } catch (lua_exception &le) {
        log_debug ("rule lua exception caught: %s", le.what ());
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_LUA");
    } catch (cxxtools::SerializationError &se) {
        log_warning ("bad json for rule %s", rulename.c_str ());
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "BAD_JSON");
    } catch (std::exception &e) {
        log_debug ("rule exception caught: %s", e.what ());
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "Internal error");
    } catch (...) {
        log_debug ("Unidentified rule exception caught!");
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "Internal error");
    }
    mlm_client_sendto (client_, mlm_client_sender (client_), RULES_SUBJECT, mlm_client_tracker (client_), 1000, &reply);
}

/// handle mailbox messages
void AlertConfig::handleMailboxMessages (zmsg_t **msg) {
    log_debug ("Handling mailbox messages");
    bool send_error = false;
    char *corr_id = nullptr;
    char *command = nullptr;
    zmsg_t *zmessage = *msg;
    if (zmessage == NULL)
        return;
    if (streq (mlm_client_subject (client_), RULES_SUBJECT)) {
        corr_id = zmsg_popstr (zmessage);
        command = zmsg_popstr (zmessage);
        log_debug ("Incoming message: subject: '%s', command: '%s'", RULES_SUBJECT, command);
        if (command != nullptr && corr_id != nullptr) {
            if (streq (command, "ERROR") || streq (corr_id, "ERROR")) {
                log_debug ("Received error message, probably some response took way too long.");
            }
            else if (streq (command, "LIST")) {
                listTemplates (corr_id, zmessage);
            }
            else if (streq (command, "PASS_RULE")) {
                passRule (corr_id, zmessage, mlm_client_sender (client_));
            }
            else if (streq (command, "ADD_TEMPLATE")) {
                addTemplate (corr_id, zmessage, mlm_client_sender (client_));
            }
            else if (streq (command, "GET_TEMPLATE")) {
                getTemplate (corr_id, zmessage);
            }
            else {
                log_error ("Received unexpected message to MAILBOX with command '%s'", command);
                send_error = true;
            }
        } else {
            send_error = true;
        }
    } else {
        send_error = true;
    }
    if (send_error) {
        if (corr_id == nullptr)
            corr_id = zmsg_popstr (zmessage);
        if (command == nullptr)
            command = zmsg_popstr (zmessage);
        log_error ("Unexpected mailbox message received with command : %s", command);
        zmsg_t *reply = zmsg_new ();
        zmsg_addstr (reply, corr_id == nullptr ? "" : corr_id);
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, "UNKNOWN_MESSAGE");
        mlm_client_sendto (client_, mlm_client_sender (client_), RULES_SUBJECT, mlm_client_tracker (client_), 1000,
                &reply);
    }
    if (corr_id != nullptr)
        zstr_free (&corr_id);
    if (command != nullptr)
        zstr_free (&command);
    zmsg_destroy (&zmessage);
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
        try {
            FullAssetSPtr assetptr = getFullAssetFromFtyProto (bmessage);
            FullAssetDatabase::getInstance ().insertOrUpdateAsset (assetptr);
        } catch (std::exception &e) {
            log_error ("Unable to create asset due to :", e.what ());
        } catch (...) {
            log_error ("Unable to create asset due to : unknown error");
        }
    } else if (streq (operation, FTY_PROTO_ASSET_OP_DELETE)) {
        try {
            const char *assetname = fty_proto_name (bmessage);
            FullAssetDatabase::getInstance ().deleteAsset (assetname);
        } catch (std::exception &e) {
            log_error ("Unable to delete asset due to :", e.what ());
        } catch (...) {
            log_error ("Unable to delete asset due to : unknown error");
        }
    }
    fty_proto_destroy (&bmessage);
}

void AlertConfig::sendRuleForAsset (FullAssetSPtr assetptr, std::shared_ptr<Rule> rule_ptr, std::string rule_name) {
    std::string json = rule_ptr->getJsonRule ();
    std::vector<std::pair<std::string, std::string>> replacements = {{"__name__", assetptr->getId ()},
            {convertTypeSubType2Name (assetptr->getTypeString (), assetptr->getSubtypeString ()), assetptr->getId ()}};
    for (auto one_replacement : replacements) {
        auto pos = json.find (one_replacement.first);
        while (pos != std::string::npos) {
            json.replace (pos, one_replacement.first.length (), one_replacement.second);
            pos = json.find (one_replacement.first, pos);
        }
    }
    zmsg_t *message = zmsg_new ();
    zmsg_addstr (message, name_.c_str ()); // uuid, no need to generate it
    zmsg_addstr (message, "ADD");
    zmsg_addstr (message, json.c_str ());
    mlm_client_sendto (client_mb_sender_, alert_trigger_mb_name_.c_str (), RULES_SUBJECT,
            mlm_client_tracker (client_), 1000, &message);
    // expect response
    void *which = zpoller_wait (client_mb_sender_poller_, timeout_internal_);
    if (which != nullptr) {
        message = mlm_client_recv (client_mb_sender_);
        assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mb_sender_));
        char *corr_id = zmsg_popstr (message);
        char *command = zmsg_popstr (message);
        if (!streq (command, "OK")) {
            char *param = zmsg_popstr (message);
            if (streq (param, "ALREADY_EXISTS")) {
                log_debug ("Rule %s for asset %s already known", rule_name.c_str (),
                        assetptr->getId ().c_str ());
            } else {
                log_error ("%s refused rule %s", alert_trigger_mb_name_.c_str (),
                        rule_ptr->getJsonRule ().c_str ());
            }
            zstr_free (&param);
        }
        zstr_free (&corr_id);
        zstr_free (&command);
        zmsg_destroy (&message);
    }
}

void AlertConfig::onAssetCreateCallback (FullAssetSPtr assetptr) {
    log_debug ("on asset create callback");
    std::map<std::string, std::shared_ptr<Rule>> rules = getAllTemplatesMap ();
    for (auto &rule_it : rules) {
        if (ruleMatchAsset (rule_it, assetptr)) {
            sendRuleForAsset (assetptr, rule_it.second, rule_it.first);
        }
    }
}
void AlertConfig::onAssetDeleteCallback (FullAssetSPtr assetptr) {
    log_debug ("on asset delete callback");
    zmsg_t *message = zmsg_new ();
    zmsg_addstr (message, name_.c_str ()); // uuid, no need to generate it
    zmsg_addstr (message, "DELETE_ELEMENT");
    zmsg_addstr (message, assetptr->getId ().c_str ());
    mlm_client_sendto (client_mb_sender_, alert_trigger_mb_name_.c_str (), RULES_SUBJECT, mlm_client_tracker (client_),
            1000, &message);
    // expect response
    void *which = zpoller_wait (client_mb_sender_poller_, timeout_internal_);
    if (which != nullptr) {
        message = mlm_client_recv (client_mb_sender_);
        assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mb_sender_));
        char *corr_id = zmsg_popstr (message);
        char *command = zmsg_popstr (message);
        if (!streq (command, "OK")) {
            char *param = zmsg_popstr (message);
            log_error ("%s refused to delete rules for asset %s", alert_trigger_mb_name_.c_str (),
                assetptr->getId ().c_str ());
            zstr_free (&param);
        }
        zstr_free (&corr_id);
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
    // clean up RW directory
    system ("rm -rf " SELFTEST_DIR_RW "/*");
    system ("cp -r " SELFTEST_DIR_RO "/templates " SELFTEST_DIR_RW);
    sleep (1);
    zactor_t *server = zactor_new (mlm_server, (void *) "Malamute");
    zstr_sendx (server, "BIND", "inproc://@/malamute", NULL);
    if (verbose)
        zstr_send (server, "VERBOSE");
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
    zstr_sendx (agent_config, "TEMPLATES_DIR", SELFTEST_DIR_RW "/templates", NULL); // rule template
    zstr_sendx (agent_config, "CONSUMER", "fty_alert_config_test_assets_stream", ".*", NULL);
    zstr_sendx (agent_config, "ALERT_TRIGGER_MB_NAME", "fty_alert_config_test_trigger", NULL); // trigger mailbox name
    sleep (1);

    log_debug ("Test 1: send asset datacenter, expected rule average.temperature@dc-1");
    // send asset - datacenter n_a
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
            char *corr_id = zmsg_popstr (zmessage);
            char *command = zmsg_popstr (zmessage);
            char *param = zmsg_popstr (zmessage);
            assert (std::string ("ADD") == command);
            assert (!std::string (param).empty ());
            auto rule_ptr = RuleFactory::createFromJson (param);
            assert (rule_ptr->getName () == "average.temperature@datacenter-1");
            // proper reply
            mlm_client_sendtox (client_mailbox, mlm_client_sender (client_mailbox), RULES_SUBJECT, corr_id, "OK",
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

    log_debug ("Test 2: send asset room, expected no rules");
    // send asset - room n_a
    // expected: empty result
    asset_aux = zhash_new ();
    zhash_autofree (asset_aux);
    zhash_insert (asset_aux, "type", (void *) "room");
    zhash_insert (asset_aux, "subtype", (void *) "n_a");
    asset_ext = zhash_new ();
    zhash_autofree (asset_ext);
    zhash_insert (asset_ext, "name", (void *) "MyRoom");
    asset = fty_proto_encode_asset (asset_aux, "room-22", FTY_PROTO_ASSET_OP_UPDATE, asset_ext);
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
            char *corr_id = zmsg_popstr (zmessage);
            char *command = zmsg_popstr (zmessage);
            char *param = zmsg_popstr (zmessage);
            assert (std::string ("ADD") == command);
            assert (!std::string (param).empty ());
            auto rule_ptr = RuleFactory::createFromJson (param);
            assert (rule_ptr->getName () == "average.humidity-input@rack-3" ||
                rule_ptr->getName () == "average.temperature-input@rack-3" ||
                rule_ptr->getName () == "phase_imbalance@rack-3" ||
                rule_ptr->getName () == "realpower.default@rack-3");
            // proper reply
            mlm_client_sendtox (client_mailbox, mlm_client_sender (client_mailbox), RULES_SUBJECT, corr_id, "OK",
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
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, "LIST");
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
            char *corr_id = zmsg_popstr (zmessage);
            char *command = zmsg_popstr (zmessage);
            char *param = zmsg_popstr (zmessage);
            assert (streq ("uuidtest", corr_id));
            assert (streq ("LIST", command));
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
    assert (rules_count == 30);

    log_debug ("Test 5: send asset room delete");
    // send asset - room n_a
    // expected: empty result
    asset_aux = zhash_new ();
    zhash_autofree (asset_aux);
    zhash_insert (asset_aux, "type", (void *) "room");
    zhash_insert (asset_aux, "subtype", (void *) "n_a");
    asset_ext = zhash_new ();
    zhash_autofree (asset_ext);
    zhash_insert (asset_ext, "name", (void *) "MyRoom");
    asset = fty_proto_encode_asset (asset_aux, "room-22", FTY_PROTO_ASSET_OP_DELETE, asset_ext);
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
            char *corr_id = zmsg_popstr (zmessage);
            char *command = zmsg_popstr (zmessage);
            char *param = zmsg_popstr (zmessage);
            assert (std::string ("DELETE_ELEMENT") == command);
            assert (std::string (param) == "room-22");
            // proper reply
            mlm_client_sendtox (client_mailbox, mlm_client_sender (client_mailbox), RULES_SUBJECT, corr_id, "OK",
                    nullptr);
            zstr_free (&command);
            zstr_free (&corr_id);
            zstr_free (&param);
            zmsg_destroy (&zmessage);
            break;
        }
    }
    assert (counter <= 20);

    log_debug ("Test 6: list rules with filter type");
    // send mailbox list, check response
    message = zmsg_new ();
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, "LIST");
    zmsg_addstr (message, "single");
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
            char *corr_id = zmsg_popstr (zmessage);
            char *command = zmsg_popstr (zmessage);
            char *param = zmsg_popstr (zmessage);
            assert (streq ("uuidtest", corr_id));
            assert (streq ("LIST", command));
            assert (streq ("single", param));
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
    assert (rules_count == 3);

    log_debug ("Test 7: list rules with filter cat");
    // send mailbox list, check response
    message = zmsg_new ();
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, "LIST");
    zmsg_addstr (message, "CAT_ENVIRONMENTAL");
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
            char *corr_id = zmsg_popstr (zmessage);
            char *command = zmsg_popstr (zmessage);
            char *param = zmsg_popstr (zmessage);
            assert (streq ("uuidtest", corr_id));
            assert (streq ("LIST", command));
            assert (streq ("CAT_ENVIRONMENTAL", param));
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
    assert (rules_count == 9);

    log_debug ("Test 8: send asset room twice, expected no rules");
    // send asset - room n_a
    // expected: empty result
    asset_aux = zhash_new ();
    zhash_autofree (asset_aux);
    zhash_insert (asset_aux, "type", (void *) "room");
    zhash_insert (asset_aux, "subtype", (void *) "n_a");
    asset_ext = zhash_new ();
    zhash_autofree (asset_ext);
    zhash_insert (asset_ext, "name", (void *) "MyRoom");
    asset = fty_proto_encode_asset (asset_aux, "room-22", FTY_PROTO_ASSET_OP_UPDATE, asset_ext);
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
    asset_aux = zhash_new ();
    zhash_autofree (asset_aux);
    zhash_insert (asset_aux, "type", (void *) "room");
    zhash_insert (asset_aux, "subtype", (void *) "n_a");
    asset_ext = zhash_new ();
    zhash_autofree (asset_ext);
    zhash_insert (asset_ext, "name", (void *) "MyRoom");
    asset = fty_proto_encode_asset (asset_aux, "room-22", FTY_PROTO_ASSET_OP_UPDATE, asset_ext);
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

    log_debug ("Test 9 send rule, expect it being passed to trigger");
    FlexibleRule fr1 ("flexible1@asset3",
        {"flexible1.metric1"},
        {"asset3"},
        {"CAT_ALL"},
        {   {"ok", {{}, "OK", "ok_description"}},
            {"fail", {{}, "CRITICAL", "fail_description"}}},
        "function main (i1) if i1 == 'good' then return 'ok' else return 'fail' end end",
        {});
    message = zmsg_new ();
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, "PASS_RULE");
    zmsg_addstr (message, fr1.getJsonRule ().c_str ());
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
            char *corr_id = zmsg_popstr (zmessage);
            char *command = zmsg_popstr (zmessage);
            if (streq (corr_id, "uuidtest")) {
                assert (streq (command, "OK"));
                ++rules_count;
            } else if (streq (command, "ADD")) {
                char *param = zmsg_popstr (zmessage);
                fr1.setSource ("fty_alert_config_test_trigger");
                assert (fr1.getJsonRule () == param);
                zstr_free (&param);
                // proper reply
                mlm_client_sendtox (client_mailbox, mlm_client_sender (client_mailbox), RULES_SUBJECT, corr_id, "OK",
                    nullptr);
                ++rules_count;
            } else {
                assert (0); // shouldn't get here
            }
            zstr_free (&command);
            zstr_free (&corr_id);
            zmsg_destroy (&zmessage);
        }
        if (rules_count == 2)
            break;
    }
    assert (counter < 20);
    assert (rules_count == 2);

    log_debug ("Test 10 send template, expect it being passed to trigger for room-22");
    FlexibleRule fr2 ("flexible2@__room_n_a__",
        {"flexible2.metric1"},
        {"__name__"},
        {"CAT_ALL"},
        {   {"ok", {{}, "OK", "ok_description"}},
            {"fail", {{}, "CRITICAL", "fail_description"}}},
        "function main (i1) if i1 == 'good' then return 'ok' else return 'fail' end end",
        {});
    message = zmsg_new ();
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, "ADD_TEMPLATE");
    zmsg_addstr (message, fr2.getJsonRule ().c_str ());
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
            char *corr_id = zmsg_popstr (zmessage);
            char *command = zmsg_popstr (zmessage);
            if (streq (corr_id, "uuidtest")) {
                assert (streq (command, "OK"));
                ++rules_count;
            } else if (streq (command, "ADD")) {
                char *param = zmsg_popstr (zmessage);
                fr2.setSource ("fty_alert_config_test_trigger");
                fr2.setName ("flexible2@room-22");
                fr2.setAssets ( {"room-22"} );
                assert (fr2.getJsonRule () == param);
                zstr_free (&param);
                // proper reply
                mlm_client_sendtox (client_mailbox, mlm_client_sender (client_mailbox), RULES_SUBJECT, corr_id, "OK",
                    nullptr);
                ++rules_count;
            } else {
                assert (0); // shouldn't get here
            }
            zstr_free (&command);
            zstr_free (&corr_id);
            zmsg_destroy (&zmessage);
        }
        if (rules_count == 2)
            break;
    }
    assert (counter < 20);
    assert (rules_count == 2);

    log_debug ("Test 11 get one single rule");
    message = zmsg_new ();
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, "GET_TEMPLATE");
    zmsg_addstr (message, "load.input_1phase@__device_epdu__");
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
            char *corr_id = zmsg_popstr (zmessage);
            char *command = zmsg_popstr (zmessage);
            char *param = zmsg_popstr (zmessage);
            assert (streq ("uuidtest", corr_id));
            assert (streq ("OK", command));
            assert (param != nullptr);
            ++rules_count;
            zstr_free (&command);
            zstr_free (&corr_id);
            zstr_free (&param);
            zmsg_destroy (&zmessage);
            break;
        }
    }
    assert (counter < 20);
    assert (rules_count == 1);

    log_debug ("Test 12 no messages in queue");
    while (counter < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which != nullptr)
            assert (false);
        ++counter;
    }
    assert (counter >= 20);

    zactor_destroy (&agent_config);
    zpoller_destroy (&poller);
    mlm_client_destroy (&client_assets);
    mlm_client_destroy (&client_mailbox);
    zactor_destroy (&server);

    printf ("OK\n");
}
