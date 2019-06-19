/*  =========================================================================
    fty_alert_trigger - Actor evaluating rules

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
    fty_alert_trigger - Actor evaluating rules
@discuss
@end
*/
#include <string>
#include <map>
#include <set>

#include "fty_alert_engine_classes.h"

ObservedGenericDatabase<std::string, std::shared_ptr<Rule>> AlertTrigger::known_rules_;
std::mutex AlertTrigger::known_rules_mutex_;
std::vector<fty_proto_t *> AlertTrigger::streamed_metrics_;
std::unordered_set<std::string> AlertTrigger::unavailable_metrics_;
std::mutex AlertTrigger::stream_metrics_mutex_;
int64_t AlertTrigger::timeout_ = fty_get_polling_interval ();

AlertTrigger::AlertTrigger (std::string name) : name_(name) {
    client_ = mlm_client_new ();
    assert (client_);
}

AlertTrigger::~AlertTrigger () {
    mlm_client_destroy (&client_);
}

void AlertTrigger::onRuleCreateCallback (RuleSPtr ruleptr) {
    zmsg_t *msg = zmsg_new ();
    zmsg_addstr (msg, "ADD");
    zmsg_addstr (msg, name_.c_str ()); // uuid don't need to be unique
    zmsg_addstr (msg, ruleptr->getJsonRule ().c_str ());
    zmsg_addstr (msg, ruleptr->getName ().c_str ());
    mlm_client_sendto (client_, alert_list_mb_name_.c_str (), LIST_RULE_MB, mlm_client_tracker (client_), 1000, &msg);
    msg = mlm_client_recv (client_);
    // thx for the reply, but I don't really care :)
    zmsg_destroy (&msg);
}

void AlertTrigger::onRuleUpdateCallback (RuleSPtr ruleptr) {
    zmsg_t *msg = zmsg_new ();
    zmsg_addstr (msg, "ADD");
    zmsg_addstr (msg, name_.c_str ()); // uuid don't need to be unique
    zmsg_addstr (msg, ruleptr->getJsonRule ().c_str ());
    zmsg_addstr (msg, ruleptr->getName ().c_str ());
    mlm_client_sendto (client_, alert_list_mb_name_.c_str (), LIST_RULE_MB, mlm_client_tracker (client_), 1000, &msg);
    msg = mlm_client_recv (client_);
    zmsg_destroy (&msg);
}

void AlertTrigger::onRuleDeleteCallback (RuleSPtr ruleptr) {
    zmsg_t *msg = zmsg_new ();
    zmsg_addstr (msg, "DELETE");
    zmsg_addstr (msg, name_.c_str ()); // uuid don't need to be unique
    zmsg_addstr (msg, ruleptr->getName ().c_str ());
    mlm_client_sendto (client_, alert_list_mb_name_.c_str (), LIST_RULE_MB, mlm_client_tracker (client_), 1000, &msg);
    msg = mlm_client_recv (client_);
    zmsg_destroy (&msg);
}

/// handle pipe messages for this actor
int AlertTrigger::handlePipeMessages (zsock_t *pipe) {
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
    if (streq (cmd, "ALERT_LIST_MB_NAME")) {
        log_debug ("ALERT_LIST_MB_NAME received");
        char* name = zmsg_popstr (msg);
        alert_list_mb_name_ = name;
        zstr_free (&name);
    }
    else
    if (streq (cmd, "PRODUCER")) {
        log_debug ("PRODUCER received");
        char* stream = zmsg_popstr (msg);
        int rv = mlm_client_set_producer (client_, stream);
        if (rv == -1)
            log_error ("%s: can't set producer on stream '%s'", name_.c_str (), stream);
        zstr_free (&stream);
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
    if (streq (cmd, "CONFIG")) {
        log_debug ("CONFIG received");
        char* filename = zmsg_popstr (msg);
        if (filename) {
            rule_location_ = filename;
        } else {
            log_error ("%s: in CONFIG command next frame is missing", name_.c_str ());
        }
        zstr_free (&filename);
    }
    zstr_free (&cmd);
    zmsg_destroy (&msg);
    return 0;
}

void AlertTrigger::listRules (std::string corr_id, std::string type, std::string ruleclass) {
    std::function<bool (const std::string & s) > filter_class, filter_type;
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
        mlm_client_sendto (client_, mlm_client_sender (client_), RULES_SUBJECT, mlm_client_tracker (client_), 1000,
                &reply);
        return;
    }
    filter_class = [&](const std::string &s) { return ruleclass.empty () || ruleclass == s; };
    zmsg_t *reply = zmsg_new ();
    zmsg_addstr (reply, "LIST");
    zmsg_addstr (reply, corr_id.c_str ());
    zmsg_addstr (reply, type.c_str ());
    zmsg_addstr (reply, ruleclass.c_str ());
    // block for lock_guard
    {
        std::lock_guard<std::mutex> lock (known_rules_mutex_);
        for (auto &r : known_rules_) {
            Rule &rule = *r.second;
            if (filter_type (rule.whoami ()) && filter_class (rule.getRuleClass ()))
                zmsg_addstr (reply, rule.getJsonRule ().c_str ());
        }
    }
    mlm_client_sendto (client_, mlm_client_sender (client_), RULES_SUBJECT,
        mlm_client_tracker (client_), 1000, &reply);
}

void AlertTrigger::getRule (std::string corr_id, std::string name) {
    zmsg_t *reply = zmsg_new ();
    try {
        std::lock_guard<std::mutex> lock (known_rules_mutex_);
        const auto &rule = known_rules_.getElement (name);
        zmsg_addstr (reply, "OK");
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, rule->getJsonRule ().c_str ());
    } catch (element_not_found &error) {
        log_debug ("not found");
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "NOT_FOUND");
    }
    mlm_client_sendto (client_, mlm_client_sender (client_), RULES_SUBJECT, mlm_client_tracker (client_), 1000, &reply);
}

void AlertTrigger::addRule (std::string corr_id, std::string json) {
    zmsg_t *reply = zmsg_new ();
    try {
        std::lock_guard<std::mutex> lock (known_rules_mutex_);
        std::shared_ptr<Rule> rule_ptr = RuleFactory::createFromJson (json);
        known_rules_.insertElement (rule_ptr->getName (), rule_ptr);
        log_debug ("rule added correctly");
        zmsg_addstr (reply, "OK");
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, json.c_str ());
    } catch (std::exception &e) {
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "Internal error");
        // TODO: FIXME: add more granularity
        /*
            log_debug ("rule already exists");
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, "ALREADY_EXISTS");

            log_warning ("rule has bad lua");
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, "BAD_LUA");

            log_error ("internal error");
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, "Internal error - operating with storage/disk failed.");

            log_warning ("default bad json for rule %s", json_representation);
            zmsg_addstr (reply, "ERROR");
            zmsg_addstr (reply, "BAD_JSON");
        */

    }
    mlm_client_sendto (client_, mlm_client_sender (client_), RULES_SUBJECT, mlm_client_tracker (client_), 1000, &reply);
}

// TODO: FIXME: should this trigger
void AlertTrigger::updateRule (std::string corr_id, std::string json, std::string old_name) {
    zmsg_t *reply = zmsg_new ();
    try {
        std::lock_guard<std::mutex> lock (known_rules_mutex_);
        std::shared_ptr<Rule> rule_ptr = RuleFactory::createFromJson (json);
        known_rules_.updateElement (old_name, rule_ptr);
        log_debug ("rule added correctly");
        zmsg_addstr (reply, "OK");
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, json.c_str ());
    } catch (element_not_found &error) {
        log_debug ("rule not found");
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "NOT_FOUND");
    } catch (std::exception &e) {
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "Internal error");
        // TODO: FIXME: add more granularity - same as above
    }
    mlm_client_sendto (client_, mlm_client_sender (client_), RULES_SUBJECT, mlm_client_tracker (client_), 1000, &reply);
}

void AlertTrigger::touchRule (std::string corr_id, std::string name) {
    zmsg_t *reply = zmsg_new ();
    std::map<std::string, std::string> metric_map;
    std::unordered_set<std::string> unavailables;
    try {
        fty::shm::shmMetrics shm_metrics;
        fty::shm::read_metrics (".*", ".*",  shm_metrics);
        // evaluate this rule
        for (fty_proto_t *metric : shm_metrics) {
            metric_map[fty_proto_name (metric)] = fty_proto_value (metric);
        }
        // put streamed metrics to map
        {
            std::lock_guard<std::mutex> lock (stream_metrics_mutex_);
            for (fty_proto_t *metric : streamed_metrics_) {
                metric_map[fty_proto_name (metric)] = fty_proto_value (metric);
            }
            unavailables = unavailable_metrics_;
        }
        {
            std::lock_guard<std::mutex> lock (known_rules_mutex_);
            auto rule_ptr = known_rules_.getElement (name);
            bool is_valid = true;
            Rule::VectorStrings metric_values;
            Alert alert (rule_ptr->getName (), Rule::ResultsMap ());
            for (std::string &metric : rule_ptr->getTargetMetrics ()) {
                if (unavailables.find (metric) != unavailables.end ()) {
                    // metric is unavailable, from stream input
                    // TODO: FIXME: this should be used if we decide to merge unavailability detection to alert engine
                    is_valid = false;
                    break;
                }
                auto metric_value = metric_map.find (metric);
                if (metric_value == metric_map.end ()) {
                    // metric was not found, it's unavailable, missing in SHM
                    // TODO: FIXME: this should be used if we decide to merge unavailability detection to alert engine
                    is_valid = false;
                    break;
                }
                metric_values.push_back (metric_value->second);
            }
            if (is_valid) {
                alert.setOutcomes (rule_ptr->evaluate (metric_values));
                alert.setState ("ACTIVE");
            } else {
                // TODO: FIXME: are alerts for unavailable metrics supposed to be resolved?
                alert.setState ("RESOLVED");
            }
            zmsg_t *msg = alert.TriggeredToFtyProto ();
            mlm_client_send (client_, alert.id ().c_str (), &msg);
        }
        // send alert on stream
        zmsg_addstr (reply, "OK");
        zmsg_addstr (reply, corr_id.c_str ());
    } catch (element_not_found &error) {
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "NOT_FOUND");
    }
    mlm_client_sendto (client_, mlm_client_sender (client_), RULES_SUBJECT, mlm_client_tracker (client_), 1000, &reply);
}

void AlertTrigger::deleteRules (std::string corr_id, RuleMatcher *matcher) {
    std::vector< std::shared_ptr<Rule> > deleted_rules;
    {
        std::lock_guard<std::mutex> lock (known_rules_mutex_);
        auto iterator = known_rules_.begin ();
        auto end_iterator = known_rules_.end ();
        for ( ; iterator != end_iterator; ) {
            if ((*matcher)(*iterator->second) == true) {
                deleted_rules.push_back (iterator->second);
                known_rules_.deleteElement (iterator->first);
                iterator++;
            } else {
                iterator++;
            }
        }
    }
    zmsg_t *reply = zmsg_new ();
    if (deleted_rules.size () > 0) {
        log_debug ("deleted rule");
        zmsg_addstr (reply, "OK");
        zmsg_addstr (reply, corr_id.c_str ());
        for (const std::shared_ptr<Rule> ruleptr : deleted_rules) {
            zmsg_addstr (reply, ruleptr->getName ().c_str ());
            // send resolved alerts for deleted rules
            Alert alert (ruleptr->getName (), Rule::ResultsMap ());
            alert.setState ("RESOLVED");
            // send alert on stream
            zmsg_t *msg = alert.TriggeredToFtyProto ();
            mlm_client_send (client_, alert.id ().c_str (), &msg);
        }
    } else {
        zmsg_addstr (reply, "ERROR");
        zmsg_addstr (reply, corr_id.c_str ());
        zmsg_addstr (reply, "NO_MATCH");
    }
    mlm_client_sendto (client_, mlm_client_sender (client_), RULES_SUBJECT, mlm_client_tracker (client_), 1000, &reply);
}

/// handle mailbox messages
void AlertTrigger::handleMailboxMessages () {
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
                char *rule_class = zmsg_popstr (zmessage);
                listRules (corr_id, param, rule_class == nullptr ? "" : rule_class);
                zstr_free (&rule_class);
            }
            else if (streq (command, "GET")) {
                getRule (corr_id, param);
            }
            else if (streq (command, "ADD")) {
                if ( zmsg_size (zmessage) == 0 ) {
                    // ADD/json
                    addRule (corr_id, param);
                }
                else {
                    // ADD/json/old_name
                    char *param1 = zmsg_popstr (zmessage);
                    updateRule (corr_id, param, param1);
                    if (param1)
                        zstr_free (&param1);
                }
            }
            else if (streq (command, "TOUCH")) {
                touchRule (corr_id, param);
            }
            else if (streq (command, "DELETE")) {
                log_info ("Requested deletion of rule '%s'", param);
                RuleNameMatcher matcher (param);
                deleteRules (corr_id, &matcher);
            }
            else if (streq (command, "DELETE_ELEMENT")) {
                log_info ("Requested deletion of rules about element '%s'", param);
                RuleAssetMatcher matcher (param);
                deleteRules (corr_id, &matcher);
            }
            else {
                log_error ("Received unexpected message to MAILBOX with command '%s'", command);
            }
        }
        zstr_free (&command);
        zstr_free (&corr_id);
        zstr_free (&param);
    } else {
        char *command = zmsg_popstr (zmessage);
        if (command != nullptr) {
            log_error ("%s: Unexpected mailbox message received with command : %s", name_.c_str (), command);
        } else {
            log_error ("%s: Unexpected mailbox message received without any commands", name_.c_str ());
        }
        zstr_free (&command);
    }
    if (zmessage) {
        zmsg_destroy (&zmessage);
    }
}

/// add messages from stream to cache
void AlertTrigger::handleStreamMessages () {
    zmsg_t *zmsg = mlm_client_recv (client_);
    std::string topic = mlm_client_subject (client_);
    if (!is_fty_proto (zmsg)) {
        // possibly METRICUNAVAILABLE
        char *command = zmsg_popstr (zmsg);
        if (streq (command, "METRICUNAVAILABLE")) {
            std::lock_guard<std::mutex> lock (stream_metrics_mutex_);
            char *metric = zmsg_popstr (zmsg);
            unavailable_metrics_.insert (metric);
            zstr_free (&metric);
        }
        zstr_free (&command);
        zmsg_destroy (&zmsg);
        return;
    }
    fty_proto_t *bmessage = fty_proto_decode (&zmsg);
    if (fty_proto_id (bmessage) != FTY_PROTO_METRIC) {
        fty_proto_destroy (&bmessage);
        return;
    }
    {
        std::lock_guard<std::mutex> lock (stream_metrics_mutex_);
        streamed_metrics_.push_back (bmessage);
    }
    fty_proto_destroy (&bmessage);
}

/// evaluate known alarms
void AlertTrigger::evaluateAlarmsForTriggers (fty::shm::shmMetrics shm_metrics) {
    // to ensure all metrics are of the same date/time, SHM metrics are all loaded at once
    // put shm metrics to metric map
    std::map<std::string, std::string> metric_map;
    std::unordered_set<std::string> unavailables;
    for (fty_proto_t *metric : shm_metrics) {
        metric_map[fty_proto_name (metric)] = fty_proto_value (metric);
    }
    // put streamed metrics to map
    {
        std::lock_guard<std::mutex> lock (stream_metrics_mutex_);
        for (fty_proto_t *metric : streamed_metrics_) {
            metric_map[fty_proto_name (metric)] = fty_proto_value (metric);
        }
        streamed_metrics_.clear ();
        unavailables = unavailable_metrics_;
        unavailable_metrics_.clear ();
    }
    {
        std::lock_guard<std::mutex> lock (known_rules_mutex_);
        for (auto &r : known_rules_) {
            Rule &rule = *r.second;
            bool is_valid = true;
            Rule::VectorStrings metric_values;
            Alert alert (rule.getName (), Rule::ResultsMap ());
            for (std::string &metric : rule.getTargetMetrics ()) {
                if (unavailables.find (metric) != unavailables.end ()) {
                    // metric is unavailable, from stream input
                    // TODO: FIXME: this should be used if we decide to merge unavailability detection to alert engine
                    is_valid = false;
                    break;
                }
                auto metric_value = metric_map.find (metric);
                if (metric_value == metric_map.end ()) {
                    // metric was not found, it's unavailable, missing in SHM
                    // TODO: FIXME: this should be used if we decide to merge unavailability detection to alert engine
                    is_valid = false;
                    break;
                }
                metric_values.push_back (metric_value->second);
            }
            if (is_valid) {
                alert.setOutcomes (rule.evaluate (metric_values));
                alert.setState ("ACTIVE");
            } else {
                // TODO: FIXME: are alerts for unavailable metrics supposed to be resolved?
                alert.setState ("RESOLVED");
            }
            // send alert on stream
            zmsg_t *msg = alert.TriggeredToFtyProto ();
            mlm_client_send (client_, alert.id ().c_str (), &msg);
        }
    }
}

void AlertTrigger::runStream (zsock_t *pipe) {
    zpoller_t *poller = zpoller_new (pipe, mlm_client_msgpipe (client_), NULL);
    assert (poller);
    int64_t timeout = timeout_;
    zsock_signal (pipe, 0);
    int64_t time_last = zclock_mono ();
    log_info ("Actor %s started",name_.c_str ());
    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, timeout);
        int64_t time_diff = zclock_mono () - time_last;
        if (time_diff >= timeout) {
            timeout = timeout_;
            // handle polling (trigger + cache clear)
            fty::shm::shmMetrics result;
            fty::shm::read_metrics (".*", ".*",  result);
            log_debug ("number of metrics read : %d", result.size ());
            evaluateAlarmsForTriggers (result);
        } else {
          timeout = timeout - time_diff;
          if (timeout > timeout_) // to speed up time in tests via pipe timeout message
              timeout = timeout_;
        }
        time_last = zclock_mono ();
        // handle expiration || termination
        if (which == NULL) {
            if (zpoller_expired (poller)) {
                continue;
            }
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
            handleStreamMessages ();
        }
    }
    zpoller_destroy (&poller);
}

void AlertTrigger::runMailbox (zsock_t *pipe) {
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
        } else {
            handleMailboxMessages ();
        }
    }
    zpoller_destroy (&poller);
}

/// trigger actor mailbox main function
void fty_alert_trigger_mailbox_main (zsock_t *pipe, void* args) {
    char *name = (char*) args;
    AlertTrigger at (name);
    at.runMailbox (pipe);
}

/// trigger actor stream main function
void fty_alert_trigger_stream_main (zsock_t *pipe, void* args) {
    char *name = (char*) args;
    AlertTrigger at (name);
    at.runStream (pipe);
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
fty_alert_trigger_test (bool verbose)
{
    printf (" * fty_alert_trigger: ");

    std::string str_SELFTEST_DIR_RW = std::string (SELFTEST_DIR_RW);
    int r = system (("rm -f " + str_SELFTEST_DIR_RW + "/*.rule").c_str ());
    assert (r == 0); // to make gcc @ CentOS 7 happy
    fty_shm_set_default_polling_interval (3);
    assert (fty_shm_set_test_dir (str_SELFTEST_DIR_RW.c_str ()) == 0);
    // create stream producer for unavailable metrics
    mlm_client_t *client_unavailable = mlm_client_new ();
    int rv = mlm_client_connect (client_unavailable, "ipc://@/malamute", 1000, "fty_alert_trigger_test_unavailable_producer");
    assert (rv == 0);
    rv = mlm_client_set_producer (client_unavailable, "fty_alert_trigger_test_unavailable");
    assert (rv == 0);
    // create stream producer for metrics stream
    mlm_client_t *client_metrics = mlm_client_new ();
    rv = mlm_client_connect (client_metrics, "ipc://@/malamute", 1000, "fty_alert_trigger_test_metrics_producer");
    assert (rv == 0);
    rv = mlm_client_set_producer (client_metrics, "fty_alert_trigger_test_metrics");
    assert (rv == 0);
    // create stream producer for metrics stream
    mlm_client_t *client_licensing = mlm_client_new ();
    rv = mlm_client_connect (client_licensing, "ipc://@/malamute", 1000, "fty_alert_trigger_test_licensing_producer");
    assert (rv == 0);
    rv = mlm_client_set_producer (client_licensing, "fty_alert_trigger_test_licensing");
    assert (rv == 0);
    // create agent for stream
    mlm_client_t *client_stream = mlm_client_new ();
    rv = mlm_client_connect (client_stream, "ipc://@/malamute", 1000, "fty_alert_trigger_test_consumer");
    assert (rv == 0);
    rv = mlm_client_set_consumer (client_licensing, "fty_alert_trigger_test_stream", ".*");
    assert (rv == 0);
    // create agent for mailboxes
    mlm_client_t *client_mailbox = mlm_client_new ();
    rv = mlm_client_connect (client_mailbox, "ipc://@/malamute", 1000, "fty_alert_trigger_test_list");
    assert (rv == 0);
    // poller
    zpoller_t *poller = zpoller_new (mlm_client_msgpipe (client_unavailable), mlm_client_msgpipe (client_metrics),
        mlm_client_msgpipe (client_licensing), mlm_client_msgpipe (client_stream), mlm_client_msgpipe (client_mailbox),
        NULL);
    assert (poller);

    // set everything up
    zactor_t *agent_trigger_stream = zactor_new (fty_alert_trigger_stream_main, (void*) "fty_alert_trigger_stream_test");
    zactor_t *agent_trigger_mailbox = zactor_new (fty_alert_trigger_mailbox_main, (void*) "fty_alert_trigger_mailbox_test");
    sleep (1);
    // trigger mailbox
    zstr_sendx (agent_trigger_mailbox, "CONFIG", SELFTEST_DIR_RW, NULL);
    zstr_sendx (agent_trigger_mailbox, "CONNECT", "ipc://@/malamute", NULL);
    zstr_sendx (agent_trigger_mailbox, "ALERT_LIST_MB_NAME", "fty_alert_trigger_test_list", NULL); // trigger mailbox name
    // trigger stream + alert evaluation
    zstr_sendx (agent_trigger_stream, "CONNECT", "ipc://@/malamute", NULL);
    zstr_sendx (agent_trigger_stream, "TIMEOUT", "3000000", NULL);
    zstr_sendx (agent_trigger_stream, "PRODUCER", "fty_alert_trigger_test_stream", NULL);
    zstr_sendx (agent_trigger_stream, "CONSUMER", "fty_alert_trigger_test_unavailable", ".*", NULL);
    zstr_sendx (agent_trigger_stream, "CONSUMER", "fty_alert_trigger_test_metrics", "status.*", NULL);
    zstr_sendx (agent_trigger_stream, "CONSUMER", "fty_alert_trigger_test_licensing", ".*", NULL);
    sleep (1);

    // TODO: FIXME:
    // create threshold rule for single metric
    ThresholdRule tr1 ("threshold1@asset1",
        {"threshold1.metric1"},
        {"asset1"},
        {"CAT_ALL"},
        {   {"ok", {{}, "OK", "ok_description"}},
            {"low_critical", {{}, "CRITICAL", "low_critical_description"}},
            {"low_warning", {{}, "WARNING", "low_warning_description"}},
            {"high_critical", {{}, "CRITICAL", "high_critical_description"}},
            {"high_warning", {{}, "WARNING", "high_warning_description"}}},
        "",
        {{"low_critical", "10"}, {"low_warning", "20"}, {"high_critical", "90"}, {"high_warning", "80"}});
    // create threshold rule for multiple metrics with lua
    ThresholdRule tr2 ("threshold2@asset2",
        {"threshold2.metric1", "threshold2.metric2"},
        {"asset2"},
        {"CAT_ALL"},
        {   {"ok", {{}, "OK", "ok_description"}},
            {"fail", {{}, "CRITICAL", "fail_description"}}},
        "function main (i1, i2) if i1 < var1 and i2 < var2 return 'ok' end return 'fail' end",
        {{"var1", "10"}, {"var2", "20"}});
    // create flexible rule with lua
    FlexibleRule fr1 ("flexible1@asset3",
        {"flexible1.metric1"},
        {"asset3"},
        {"CAT_ALL"},
        {   {"ok", {{}, "OK", "ok_description"}},
            {"fail", {{}, "CRITICAL", "fail_description"}}},
        "function main (i1) if i1 == 'good' return 'ok' end return 'fail' end",
        {});
    // create single rule with lua
    SingleRule sr1 ("single1@asset4",
        {"single1.metric1"},
        {"asset4"},
        {"CAT_ALL"},
        {   {"ok", {{}, "OK", "ok_description"}},
            {"fail", {{}, "CRITICAL", "fail_description"}}},
        "function main (i1) if i1 < var1 return 'ok' end return 'fail' end",
        {{"var1", "50"}});
    // create pattern rule with lua
    PatternRule pr1 ("pattern1@asset5",
        {"pattern.*.metric1"},
        {"asset5"},
        {"CAT_ALL"},
        {   {"ok", {{}, "OK", "ok_description"}},
            {"fail", {{}, "CRITICAL", "fail_description"}}},
        "function main (i1) if i1 < var1 return 'ok' end return 'fail' end",
        {{"var1", "50"}});

    // send mailbox add, check response
    zmsg_t *message = zmsg_new ();
    zmsg_addstr (message, "ADD");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, tr1.getJsonRule ().c_str ());
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    int counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "OK"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
        } else if (which != nullptr) {
            assert (false); // unexpected message
        }
    }
    assert (counter < 20);
    message = zmsg_new ();
    zmsg_addstr (message, "ADD");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, tr2.getJsonRule ().c_str ());
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "OK"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
        } else if (which != nullptr) {
            assert (false); // unexpected message
        }
    }
    assert (counter < 20);
    message = zmsg_new ();
    zmsg_addstr (message, "ADD");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, fr1.getJsonRule ().c_str ());
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "OK"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
        } else if (which != nullptr) {
            assert (false); // unexpected message
        }
    }
    assert (counter < 20);
    message = zmsg_new ();
    zmsg_addstr (message, "ADD");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, sr1.getJsonRule ().c_str ());
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "OK"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
        } else if (which != nullptr) {
            assert (false); // unexpected message
        }
    }
    assert (counter < 20);
    message = zmsg_new ();
    zmsg_addstr (message, "ADD");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, pr1.getJsonRule ().c_str ());
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "OK"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
        } else if (which != nullptr) {
            assert (false); // unexpected message
        }
    }
    assert (counter < 20);

    // send mailbox add (on known, should fail)
    message = zmsg_new ();
    zmsg_addstr (message, "ADD");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, pr1.getJsonRule ().c_str ());
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "ERROR"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
        } else if (which != nullptr) {
            assert (false); // unexpected message
        }
    }
    assert (counter < 20);

    // send mailbox list, check response
    message = zmsg_new ();
    zmsg_addstr (message, "LIST");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, "all");
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    counter = 0;
    int rules_count = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "LIST"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            char *param1 = zmsg_popstr (message);
            char *param2 = zmsg_popstr (message);
            for (;;) {
                char *rules = zmsg_popstr (message);
                ++rules_count;
                if (rules == nullptr)
                    break;
            }
            zstr_free (&param1);
            zstr_free (&param2);
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
        } else if (which != nullptr) {
            assert (false); // unexpected message
        }
    }
    assert (counter < 20);
    assert (rules_count == 5);

    // send mailbox get
    message = zmsg_new ();
    zmsg_addstr (message, "GET");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, "single1@asset4");
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "OK"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            char *param1 = zmsg_popstr (message);
            assert (param1 != nullptr);
            zstr_free (&param1);
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
        } else if (which != nullptr) {
            assert (false); // unexpected message
        }
    }
    assert (counter < 20);

    // send metrics via stream, evaluate all 5 rules
    // rule tr1
    zmsg_t *m = fty_proto_encode_metric (nullptr, ::time (nullptr), ::time (nullptr), "threshold1.metric1", "asset1",
            "15.00", "");
    mlm_client_send (client_metrics, "threshold1.metric1@asset1", &m);
    // rule tr2
    m = fty_proto_encode_metric (nullptr, ::time (nullptr), ::time (nullptr), "threshold2.metric1", "asset2", "14.00",
            "");
    mlm_client_send (client_metrics, "threshold2.metric1@asset2", &m);
    m = fty_proto_encode_metric (nullptr, ::time (nullptr), ::time (nullptr), "threshold2.metric2", "asset2", "12.00",
            "");
    mlm_client_send (client_metrics, "threshold2.metric2@asset2", &m);
    // rule fr1
    m = fty_proto_encode_metric (nullptr, ::time (nullptr), ::time (nullptr), "flexible1.metric1", "asset3", "bad", "");
    mlm_client_send (client_metrics, "flexible1.metric1@asset3", &m);
    // rule sr1
    m = fty_proto_encode_metric (nullptr, ::time (nullptr), ::time (nullptr), "single1.metric1", "asset4", "9.00", "");
    mlm_client_send (client_metrics, "single1.metric1@asset4", &m);
    // rule pr1
    m = fty_proto_encode_metric (nullptr, ::time (nullptr), ::time (nullptr), "pattern1.metric1", "asset5", "8.00", "");
    mlm_client_send (client_metrics, "pattern1.metric1@asset5", &m);
    // timeout it updated on every timeout and when it's set to lower value than it's current
    // unfortunatelly this needs two passes, as timeout handling is the first thing and parsing message is the second
    // so the first timeout sets the value to 1000, but the second actually propagates it to the poller timeout, even
    // through it sets it to 300000 afterwards. Then poller will time out in up to 1000ms and reset it's value to 300000
    zstr_sendx (agent_trigger_stream, "TIMEOUT", "1000", NULL); // speed up evaluation
    zstr_sendx (agent_trigger_stream, "TIMEOUT", "300000", NULL); // slow down evaluation to get time for results + prep
    sleep (1);
    std::set<std::string> recv_alarms;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_stream)) {
            message = mlm_client_recv (client_stream);
            assert (std::string ("threshold1@asset1") == mlm_client_subject (client_stream) ||
                    std::string ("threshold2@asset2") == mlm_client_subject (client_stream) ||
                    std::string ("flexible1@asset3") == mlm_client_subject (client_stream) ||
                    std::string ("single1@asset4") == mlm_client_subject (client_stream) ||
                    std::string ("pattern1@asset5") == mlm_client_subject (client_stream));
            Alert a (mlm_client_subject (client_stream), {});
            fty_proto_t *fty_msg = fty_proto_decode (&message);
            a.overwrite (fty_msg);
            recv_alarms.insert (a.id ());
            assert (a.state () == "ACTIVE"); // all alarms should be active
            // TODO: FIXME: add more precise unit tests
            fty_proto_destroy (&fty_msg);
        } else {
            assert (false); // unexpected message from other sources
        }
    }
    assert (counter < 20);
    assert (recv_alarms.size () == 5); // all alarms should be triggered
    recv_alarms.clear ();

    // send metrics via shm, evaluate all 5 rules
    fty_shm_delete_test_dir ();
    fty_shm_set_test_dir (str_SELFTEST_DIR_RW.c_str ());
    fty::shm::write_metric ("asset1", "threshold1.metric1", "85.00", "", 5);
    fty::shm::write_metric ("asset2", "threshold2.metric1", "86.00", "", 5);
    fty::shm::write_metric ("asset2", "threshold2.metric2", "87.00", "", 5);
    fty::shm::write_metric ("asset3", "flexible1.metric1", "bad", "", 5);
    fty::shm::write_metric ("asset4", "single1.metric1", "91.00", "", 5);
    fty::shm::write_metric ("asset5", "pattern1.metric1", "92.00", "", 5);
    zstr_sendx (agent_trigger_stream, "TIMEOUT", "1000", NULL); // speed up evaluation
    zstr_sendx (agent_trigger_stream, "TIMEOUT", "300000", NULL); // slow down evaluation to get time for results + prep
    sleep (1);
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_stream)) {
            message = mlm_client_recv (client_stream);
            assert (std::string ("threshold1@asset1") == mlm_client_subject (client_stream) ||
                    std::string ("threshold2@asset2") == mlm_client_subject (client_stream) ||
                    std::string ("flexible1@asset3") == mlm_client_subject (client_stream) ||
                    std::string ("single1@asset4") == mlm_client_subject (client_stream) ||
                    std::string ("pattern1@asset5") == mlm_client_subject (client_stream));
            Alert a (mlm_client_subject (client_stream), {});
            fty_proto_t *fty_msg = fty_proto_decode (&message);
            a.overwrite (fty_msg);
            recv_alarms.insert (a.id ());
            assert (a.state () == "ACTIVE"); // all alarms should be active
            // TODO: FIXME: add more precise unit tests
            fty_proto_destroy (&fty_msg);
        } else {
            assert (false); // unexpected message from other sources
        }
    }
    assert (counter < 20);
    assert (recv_alarms.size () == 5); // all alarms should be triggered
    recv_alarms.clear ();

    // send metrics via both stream and shm, evaluate multi metrics rules
    fty_shm_delete_test_dir ();
    fty_shm_set_test_dir (str_SELFTEST_DIR_RW.c_str ());
    m = fty_proto_encode_metric (nullptr, ::time (nullptr), ::time (nullptr), "threshold2.metric1", "asset2", "9.00",
            "");
    mlm_client_send (client_metrics, "threshold2.metric1@asset2", &m);
    fty::shm::write_metric ("asset2", "threshold2.metric2", "8.00", "", 5);
    zstr_sendx (agent_trigger_stream, "TIMEOUT", "1000", NULL); // speed up evaluation
    zstr_sendx (agent_trigger_stream, "TIMEOUT", "300000", NULL); // slow down evaluation to get time for results + prep
    sleep (1);
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_stream)) {
            message = mlm_client_recv (client_stream);
            assert (std::string ("threshold2@asset2") == mlm_client_subject (client_stream));
            Alert a (mlm_client_subject (client_stream), {});
            fty_proto_t *fty_msg = fty_proto_decode (&message);
            a.overwrite (fty_msg);
            recv_alarms.insert (a.id ());
            assert (a.state () == "ACTIVE"); // all alarms should be active
            // TODO: FIXME: add more precise unit tests
            fty_proto_destroy (&fty_msg);
        } else {
            assert (false); // unexpected message from other sources
        }
    }
    assert (counter < 20);
    assert (recv_alarms.size () == 1); // all alarms should be triggered
    recv_alarms.clear ();

    // send metric unavailable for single metric rules
    m = zmsg_new ();
    assert (m);
    zmsg_addstr (m, "METRICUNAVAILABLE");
    zmsg_addstr (m, "threshold1.metric1@asset1");
    rv = mlm_client_send (client_unavailable, "threshold1.metric1@asset1", &m);
    assert (rv == 0);
    zstr_sendx (agent_trigger_stream, "TIMEOUT", "1000", NULL); // speed up evaluation
    zstr_sendx (agent_trigger_stream, "TIMEOUT", "300000", NULL); // slow down evaluation to get time for results + prep
    sleep (1);
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_stream)) {
            message = mlm_client_recv (client_stream);
            assert (std::string ("threshold1@asset1") == mlm_client_subject (client_stream));
            Alert a (mlm_client_subject (client_stream), {});
            fty_proto_t *fty_msg = fty_proto_decode (&message);
            a.overwrite (fty_msg);
            recv_alarms.insert (a.id ());
            assert (a.state () == "RESOLVED"); // all alarms should be active
            // TODO: FIXME: add more precise unit tests
            fty_proto_destroy (&fty_msg);
        } else {
            assert (false); // unexpected message from other sources
        }
    }
    assert (counter < 20);
    assert (recv_alarms.size () == 1); // all alarms should be triggered
    recv_alarms.clear ();

    // send metric unavailable for multi metric rules
    m = zmsg_new ();
    assert (m);
    zmsg_addstr (m, "METRICUNAVAILABLE");
    zmsg_addstr (m, "threshold2.metric1@asset2");
    rv = mlm_client_send (client_unavailable, "threshold2.metric1@asset2", &m);
    assert (rv == 0);
    zstr_sendx (agent_trigger_stream, "TIMEOUT", "1000", NULL); // speed up evaluation
    zstr_sendx (agent_trigger_stream, "TIMEOUT", "300000", NULL); // slow down evaluation to get time for results + prep
    sleep (1);
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_stream)) {
            message = mlm_client_recv (client_stream);
            assert (std::string ("threshold2@asset2") == mlm_client_subject (client_stream));
            Alert a (mlm_client_subject (client_stream), {});
            fty_proto_t *fty_msg = fty_proto_decode (&message);
            a.overwrite (fty_msg);
            recv_alarms.insert (a.id ());
            assert (a.state () == "RESOLVED"); // all alarms should be active
            // TODO: FIXME: add more precise unit tests
            fty_proto_destroy (&fty_msg);
        } else {
            assert (false); // unexpected message from other sources
        }
    }
    assert (counter < 20);
    assert (recv_alarms.size () == 1); // all alarms should be triggered
    recv_alarms.clear ();

    // send mailbox touch, check result
    fty_shm_delete_test_dir ();
    fty_shm_set_test_dir (str_SELFTEST_DIR_RW.c_str ());
    fty::shm::write_metric ("asset1", "threshold1.metric1", "85.00", "", 5);
    message = zmsg_new ();
    zmsg_addstr (message, "TOUCH");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, "single1@asset4");
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "OK"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
        } if (which == mlm_client_msgpipe (client_stream)) {
            message = mlm_client_recv (client_stream);
            assert (std::string ("threshold1@asset1") == mlm_client_subject (client_stream));
            Alert a (mlm_client_subject (client_stream), {});
            fty_proto_t *fty_msg = fty_proto_decode (&message);
            a.overwrite (fty_msg);
            recv_alarms.insert (a.id ());
            assert (a.state () == "ACTIVE"); // all alarms should be active
            // TODO: FIXME: add more precise unit tests
            fty_proto_destroy (&fty_msg);
        } else {
            assert (false); // no more messages expected
        }
    }
    assert (counter < 20);
    assert (recv_alarms.size () == 1); // all alarms should be triggered
    recv_alarms.clear ();

    // send mailbox add (update)
    PatternRule pr2 ("pattern1@asset5",
        {"pattern.*.metric1"},
        {"asset5"},
        {"CAT_ALL"},
        {   {"ok", {{}, "OK", "ok_description"}},
            {"fail", {{}, "CRITICAL", "fail_description"}}},
        "function main (i1) if i1 < var1 return 'ok' end return 'fail' end",
        {{"var1", "60"}});
    pr2.setRuleDescription ("DESCRIPTION");
    message = zmsg_new ();
    zmsg_addstr (message, "ADD");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, pr2.getJsonRule ().c_str ());
    zmsg_addstr (message, "pattern1@asset5");
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "OK"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
        } else if (which != nullptr) {
            assert (false); // unexpected message
        }
    }
    assert (counter < 20);
    message = zmsg_new ();
    zmsg_addstr (message, "GET");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, "pattern1@asset5");
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "OK"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            char *param1 = zmsg_popstr (message);
            std::shared_ptr<Rule> rule_ptr = RuleFactory::createFromJson (param1);
            assert (rule_ptr->getRuleDescription () == "DESCRIPTION");
            assert (param1 != nullptr);
            zstr_free (&param1);
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
        } else if (which != nullptr) {
            assert (false); // unexpected message
        }
    }
    assert (counter < 20);

    // send mailbox delete
    message = zmsg_new ();
    zmsg_addstr (message, "DELETE");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, "pattern1@asset5");
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "OK"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
        } if (which == mlm_client_msgpipe (client_stream)) {
            message = mlm_client_recv (client_stream);
            assert (std::string ("threshold1@asset1") == mlm_client_subject (client_stream));
            Alert a (mlm_client_subject (client_stream), {});
            fty_proto_t *fty_msg = fty_proto_decode (&message);
            a.overwrite (fty_msg);
            recv_alarms.insert (a.id ());
            assert (a.state () == "RESOLVED"); // all alarms should be active
            // TODO: FIXME: add more precise unit tests
            fty_proto_destroy (&fty_msg);
        } else if (which != nullptr) {
            assert (false); // unexpected message
        }
    }
    assert (counter < 20);
    message = zmsg_new ();
    zmsg_addstr (message, "GET");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, "pattern1@asset5");
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "ERROR"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            // TODO: FIXME: add more details to this UI
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
            break;
        } else if (which != nullptr) {
            assert (false); // unexpected message
        }
    }
    assert (counter < 20);

    // send mailbox delete element
    message = zmsg_new ();
    zmsg_addstr (message, "DELETE_ELEMENT");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, "asset4");
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "OK"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            // TODO: FIXME: add more precise unit tests
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
        } if (which == mlm_client_msgpipe (client_stream)) {
            message = mlm_client_recv (client_stream);
            assert (std::string ("single1@asset4") == mlm_client_subject (client_stream));
            Alert a (mlm_client_subject (client_stream), {});
            fty_proto_t *fty_msg = fty_proto_decode (&message);
            a.overwrite (fty_msg);
            recv_alarms.insert (a.id ());
            assert (a.state () == "RESOLVED"); // all alarms should be active
            // TODO: FIXME: add more precise unit tests
            fty_proto_destroy (&fty_msg);
        } else if (which != nullptr) {
            assert (false); // unexpected message
        }
    }
    assert (counter < 20);
    message = zmsg_new ();
    zmsg_addstr (message, "GET");
    zmsg_addstr (message, "uuidtest"); // uuid, no need to generate it
    zmsg_addstr (message, "single1@asset4");
    mlm_client_sendto (client_mailbox, "fty_alert_trigger_mailbox_test", RULES_SUBJECT,
        mlm_client_tracker (client_mailbox), 1000, &message);
    // expect response
    counter = 0;
    while (counter++ < 20) {
        void *which = zpoller_wait (poller, 1000);
        if (which == mlm_client_msgpipe (client_mailbox)) {
            message = mlm_client_recv (client_mailbox);
            assert (std::string (RULES_SUBJECT) == mlm_client_subject (client_mailbox));
            char *command = zmsg_popstr (message);
            assert (streq (command, "ERROR"));
            char *corr_id = zmsg_popstr (message);
            assert (streq (corr_id, "uuidtest"));
            // TODO: FIXME: add more details to this UI
            zstr_free (&corr_id);
            zstr_free (&command);
            zmsg_destroy (&message);
            break;
        } else if (which != nullptr) {
            assert (false); // unexpected message
        }
    }
    assert (counter < 20);

    // send licensing metric
    // TODO: FIXME: add this as there was no support in previous version

    zpoller_destroy (&poller);
    mlm_client_destroy (&client_unavailable);
    mlm_client_destroy (&client_metrics);
    mlm_client_destroy (&client_licensing);
    mlm_client_destroy (&client_stream);
    mlm_client_destroy (&client_mailbox);
    zactor_destroy (&agent_trigger_stream);
    zactor_destroy (&agent_trigger_mailbox);
    printf ("OK\n");
}
