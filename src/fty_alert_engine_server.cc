/*  =========================================================================
    fty_alert_engine_server - Actor evaluating rules

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
    =========================================================================
*/

/*
@header
    fty_alert_engine_server - Actor evaluating rules
@discuss
@end
*/
#include "alertconfiguration.h"
#include "autoconfig.h"
#include <algorithm>
#include <cxxtools/directory.h>
#include <fty_shm.h>
#include <functional>
#include <lua.h>
#include <math.h>
#include <mutex>
#include <sstream>
#include <string.h>
#include <unordered_map>
#include <vector>

#define METRICS_STREAM "METRICS"

// #include "fty_alert_engine_classes.h"

#include "fty_alert_engine_audit_log.h"

// object use by stream and mailbox messages
static AlertConfiguration alertConfiguration;

// Mutex to manage the alertConfiguration object access
static std::mutex mtxAlertConfig;

// map to know if a metric is evaluted or not
static std::map<std::string, bool> evaluateMetrics;

void clearEvaluateMetrics()
{
    evaluateMetrics.clear();
}

// static
void list_rules(mlm_client_t* client, const char* type, const char* ruleclass, AlertConfiguration& ac)
{
    std::function<bool(const std::string& s)> filter_f;
    if (streq(type, "all")) {
        filter_f = [](const std::string& /* s */) {
            return true;
        };
    } else if (streq(type, "threshold")) {
        filter_f = [](const std::string& s) {
            return s.compare("threshold") == 0;
        };
    } else if (streq(type, "single")) {
        filter_f = [](const std::string& s) {
            return s.compare("single") == 0;
        };
    } else if (streq(type, "pattern")) {
        filter_f = [](const std::string& s) {
            return s.compare("pattern") == 0;
        };
    } else {
        // invalid type
        log_warning("type '%s' is invalid", type);
        zmsg_t* reply = zmsg_new();
        zmsg_addstr(reply, "ERROR");
        zmsg_addstr(reply, "INVALID_TYPE");
        mlm_client_sendto(client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
        return;
    }

    std::string rclass;
    if (ruleclass) {
        rclass = ruleclass;
    }
    zmsg_t* reply = zmsg_new();
    zmsg_addstr(reply, "LIST");
    zmsg_addstr(reply, type);
    zmsg_addstr(reply, rclass.c_str());
    // std::vector <
    //  std::pair <
    //      RulePtr,
    //      std::vector<PureAlert>
    //      >
    // >
    log_debug("number of all rules = '%zu'", ac.size());
    mtxAlertConfig.lock();
    for (const auto& i : ac) {
        const auto& rule = i.second.first;
        if (!(filter_f(rule->whoami()) && (rclass.empty() || rule->rule_class() == rclass))) {
            log_debug("Skipping rule  = '%s' class '%s'", rule->name().c_str(), rule->rule_class().c_str());
            continue;
        }
        log_debug("Adding rule  = '%s'", rule->name().c_str());
        zmsg_addstr(reply, rule->getJsonRule().c_str());
    }
    mtxAlertConfig.unlock();
    mlm_client_sendto(client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
}

// static
void get_rule(mlm_client_t* client, const char* name, AlertConfiguration& ac)
{
    assert(name != NULL);
    zmsg_t* reply = zmsg_new();
    bool    found = false;

    mtxAlertConfig.lock();
    log_debug("number of all rules = '%zu'", ac.size());
    if (ac.count(name) != 0) {
        const auto& it_ac = ac.at(name);
        const auto& rule  = it_ac.first;
        log_debug("found rule %s", name);
        zmsg_addstr(reply, "OK");
        zmsg_addstr(reply, rule->getJsonRule().c_str());
        found = true;
    }

    mtxAlertConfig.unlock();

    if (!found) {
        log_debug("not found");
        zmsg_addstr(reply, "ERROR");
        zmsg_addstr(reply, "NOT_FOUND");
    }
    mlm_client_sendto(client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
}


// XXX: Store the actions as zlist_t internally to avoid useless copying
zlist_t* makeActionList(const std::vector<std::string>& actions)
{
    zlist_t* res = zlist_new();
    for (const auto& oneAction : actions) {
        zlist_append(res, const_cast<char*>(oneAction.c_str()));
    }
    return res;
}

// static
void send_alerts(mlm_client_t* client, const std::vector<PureAlert>& alertsToSend, const std::string& rule_name)
{
    for (const auto& alert : alertsToSend) {
        // Asset id is missing in the rule name for warranty alarms
        std::string fullRuleName = rule_name;
        if (streq("warranty", fullRuleName.c_str())) {
            fullRuleName += "@" + alert._element;
        }

        zlist_t* actions = makeActionList(alert._actions);
        zmsg_t*  msg     = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)),
            static_cast<uint32_t>(alert._ttl), fullRuleName.c_str(), alert._element.c_str(), alert._status.c_str(),
            alert._severity.c_str(), alert._description.c_str(), actions);
        zlist_destroy(&actions);
        if (msg) {
            std::string atopic = rule_name + "/" + alert._severity + "@" + alert._element;
            mlm_client_send(client, atopic.c_str(), &msg);
            log_info("Send Alert for %s with state %s and severity %s", fullRuleName.c_str(), alert._status.c_str(),
                alert._severity.c_str());
        }
    }
}

// static
void send_alerts(mlm_client_t* client, const std::vector<PureAlert>& alertsToSend, const RulePtr& rule)
{
    send_alerts(client, alertsToSend, rule->name());
}

// static
void add_rule(mlm_client_t* client, const char* json_representation, AlertConfiguration& ac)
{
    std::istringstream           f(json_representation);
    std::set<std::string>        newSubjectsToSubscribe;
    std::vector<PureAlert>       alertsToSend;
    AlertConfiguration::iterator new_rule_it;

    mtxAlertConfig.lock();
    int rv = ac.addRule(f, newSubjectsToSubscribe, alertsToSend, new_rule_it);
    mtxAlertConfig.unlock();

    zmsg_t* reply = zmsg_new();
    switch (rv) {
        case -2: {
            // rule exists
            log_debug("rule already exists");
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "ALREADY_EXISTS");

            mlm_client_sendto(
                client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            return;
        }
        case 0: {
            // rule was created succesfully
            /* TODO: WIP, don't delete
            log_debug ("newsubjects count = %d", newSubjectsToSubscribe.size () );
            log_debug ("alertsToSend count = %d", alertsToSend.size () );
            for ( const auto &interestedSubject : newSubjectsToSubscribe ) {
                log_debug ("Registering to receive '%s'", interestedSubject.c_str ());
                mlm_client_set_consumer (client, METRICS_STREAM, interestedSubject.c_str ());
                log_debug ("Registering finished");
            }
             */

            // send a reply back
            log_debug("rule added correctly");
            zmsg_addstr(reply, "OK");
            zmsg_addstr(reply, json_representation);
            mlm_client_sendto(
                client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);

            // send updated alert
            send_alerts(client, alertsToSend, new_rule_it->second.first);
            return;
        }
        case -5: {
            log_warning("rule has bad lua");
            // error during the rule creation (lua)
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "BAD_LUA");

            mlm_client_sendto(
                client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            return;
        }
        case -6: {
            log_error("internal error");
            // error during the rule creation (lua)
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "Internal error - operating with storage/disk failed.");

            mlm_client_sendto(
                client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            return;
        }
        case -100: // PQSWMBT-3723 rule can't be directly instantiated
        {
            log_debug("rule can't be directly instantiated");
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "Rule can't be directly instantiated.");

            mlm_client_sendto(
                client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            return;
        }
        default: {
            // error during the rule creation
            log_warning("default bad json for rule %s", json_representation);
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "BAD_JSON");

            mlm_client_sendto(
                client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            return;
        }
    }
}

// static
void update_rule(mlm_client_t* client, const char* json_representation, const char* rule_name, AlertConfiguration& ac)
{
    std::istringstream           f(json_representation);
    std::set<std::string>        newSubjectsToSubscribe;
    std::vector<PureAlert>       alertsToSend;
    AlertConfiguration::iterator new_rule_it;
    mtxAlertConfig.lock();
    int rv = ac.updateRule(f, rule_name, newSubjectsToSubscribe, alertsToSend, new_rule_it);
    mtxAlertConfig.unlock();
    zmsg_t* reply = zmsg_new();
    switch (rv) {
        case -2: {
            log_debug("rule not found");
            // ERROR rule doesn't exist
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "NOT_FOUND");
            mlm_client_sendto(
                client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            return;
        }
        case 0: {
            // rule was updated succesfully
            /* TODO: WIP, don't delete
            log_debug ("newsubjects count = %d", newSubjectsToSubscribe.size () );
            log_debug ("alertsToSend count = %d", alertsToSend.size () );
            for ( const auto &interestedSubject : newSubjectsToSubscribe ) {
                log_debug ("Registering to receive '%s'", interestedSubject.c_str ());
                mlm_client_set_consumer (client, METRICS_STREAM, interestedSubject.c_str ());
                log_debug ("Registering finished");
            }
             */
            // send a reply back
            log_debug("rule updated");
            zmsg_addstr(reply, "OK");
            zmsg_addstr(reply, json_representation);
            mlm_client_sendto(
                client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            // send updated alert
            send_alerts(client, alertsToSend, new_rule_it->second.first);
            return;
        }
        case -5: {
            log_warning("rule has incorrect lua");
            // error during the rule creation (lua)
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "BAD_LUA");
            mlm_client_sendto(
                client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            return;
        }
        case -3: {
            log_debug("new rule name already exists");
            // rule with new rule name already exists
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "ALREADY_EXISTS");
            mlm_client_sendto(
                client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            return;
        }
        case -6: {
            // error during the rule creation
            log_error("internal error");
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "Internal error - operating with storage/disk failed.");
            mlm_client_sendto(
                client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            return;
        }

        default: {
            // error during the rule creation
            log_warning("bad json default for %s", json_representation);
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "BAD_JSON");
            mlm_client_sendto(
                client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            return;
        }
    }
}

static void delete_rules(mlm_client_t* client, RuleMatcher* matcher, AlertConfiguration& ac)
{
    std::map<std::string, std::vector<PureAlert>> alertsToSend;
    std::vector<std::string>                      rulesDeleted;
    mtxAlertConfig.lock();
    zmsg_t* reply = zmsg_new();
    int     rv    = ac.deleteRules(matcher, alertsToSend, rulesDeleted);
    if (!rv) {
        if (rulesDeleted.empty()) {
            log_debug("can't delete rule (no match)");
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "NO_MATCH");
        } else {
            log_debug("deleted rule");
            zmsg_addstr(reply, "OK");
            for (const auto& i : rulesDeleted) {
                zmsg_addstr(reply, i.c_str());
            }
            std::for_each(alertsToSend.begin(), alertsToSend.end(),
                // reference skipped because for_each doesn't like it
                [client](std::pair<std::string, std::vector<PureAlert>> alerts) {
                    send_alerts(client, alerts.second, alerts.first);
                });
        }
    } else {
        log_debug("can't delete rule (failure during removal)");
        zmsg_addstr(reply, "ERROR");
        zmsg_addstr(reply, "FAILURE_RULE_REMOVAL");
    }

    mlm_client_sendto(client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
    mtxAlertConfig.unlock();
}


// static
void touch_rule(mlm_client_t* client, const char* rule_name, AlertConfiguration& ac, bool send_reply)
{
    std::vector<PureAlert> alertsToSend;

    mtxAlertConfig.lock();
    int rv = ac.touchRule(rule_name, alertsToSend);
    mtxAlertConfig.unlock();
    switch (rv) {
        case -1: {
            log_error("touch_rule:%s: Rule was not found", rule_name);
            // ERROR rule doesn't exist
            if (send_reply) {
                zmsg_t* reply = zmsg_new();
                if (!reply) {
                    log_error("touch_rule:%s: Cannot create reply message.", rule_name);
                    return;
                }
                zmsg_addstr(reply, "ERROR");
                zmsg_addstr(reply, "NOT_FOUND");
                mlm_client_sendto(
                    client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            }
            return;
        }
        case 0: {
            // rule was touched
            // send a reply back
            log_debug("touch_rule:%s: ok", rule_name);
            if (send_reply) {
                zmsg_t* reply = zmsg_new();
                if (!reply) {
                    log_error("touch_rule:%s: Cannot create reply message.", rule_name);
                    return;
                }
                zmsg_addstr(reply, "OK");
                mlm_client_sendto(
                    client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
            }
            // send updated alert
            send_alerts(client, alertsToSend, rule_name); // TODO third parameter
            return;
        }
    }
}

void check_metrics(mlm_client_t* client, const char* metric_topic, AlertConfiguration& ac)
{
    const std::vector<std::string> rules_of_metric = ac.getRulesByMetric(metric_topic);
    for (const auto& rulename : rules_of_metric) {
        touch_rule(client, rulename.c_str(), ac, false);
    }
}

// static
bool evaluate_metric(mlm_client_t* client, const MetricInfo& triggeringMetric, const MetricList& knownMetricValues,
    AlertConfiguration& ac)
{
    // Go through all known rules, and try to evaluate them
    mtxAlertConfig.lock();
    bool isEvaluate = false;

    std::string sTopic;
    // end_warranty_date is the only "regex rule", for optimisation purpose, use some trick for those.
    if (triggeringMetric.getSource() == "end_warranty_date")
        sTopic = "^end_warranty_date@.+";
    else
        sTopic = triggeringMetric.generateTopic();

    const std::vector<std::string> rules_of_metric = ac.getRulesByMetric(sTopic);

    log_debug(" ### evaluate topic '%s' (rules size: %zu)", sTopic.c_str(), rules_of_metric.size());

    for (const auto& rulename : rules_of_metric) {
        if (ac.count(rulename) == 0) {
            log_error("Rule %s must exist but was not found", rulename.c_str());
            continue;
        }

        auto&       it_ac = ac.at(rulename);
        const auto& rule  = it_ac.first;
        log_debug(" ### Evaluate rule '%s'", rule->name().c_str());

        try {
            isEvaluate = true;
            PureAlert pureAlert;
            int       rv = rule->evaluate(knownMetricValues, pureAlert);
            if (rv != 0) {
                log_error(" ### Cannot evaluate the rule '%s'", rule->name().c_str());
                continue;
            }

            PureAlert alertToSend;
            rv               = ac.updateAlert(it_ac, pureAlert, alertToSend);
            alertToSend._ttl = triggeringMetric.getTtl() * 3;

            // NOTE: Warranty rule is not processed by configurator which adds info about asset. In order to send the
            // corrent message to stream alert description is modified
            if (rule->name() == "warranty") {
                int remaining_days = static_cast<int>(triggeringMetric.getValue());
                if (alertToSend._description == "{\"key\":\"TRANSLATE_LUA (Warranty expired)\"}") {
                    remaining_days = abs(remaining_days);
                    alertToSend._description =
                        std::string(
                            "{\"key\" : \"TRANSLATE_LUA (Warranty on {{asset}} expired {{days}} days ago.)\", ") +
                        "\"variables\" : { \"asset\" : { \"value\" : \"\", \"assetLink\" : \"" +
                        triggeringMetric.getElementName() + "\" }, \"days\" : \"" + std::to_string(remaining_days) +
                        "\"} }";
                } else if (alertToSend._description == "{\"key\":\"TRANSLATE_LUA (Warranty expires in)\"}") {
                    alertToSend._description = std::string(
                                                   "{\"key\" : \"TRANSLATE_LUA (Warranty on {{asset}} expires in less "
                                                   "than {{days}} days.)\", ") +
                                               "\"variables\" : { \"asset\" : { \"value\" : \"\", \"assetLink\" : \"" +
                                               triggeringMetric.getElementName() + "\" }, \"days\" : \"" +
                                               std::to_string(remaining_days) + "\"} }";
                } else {
                    log_error("Unable to identify Warranty alert description");
                }
            }

            if (rv == -1) {
                log_debug(" ### alert updated, nothing to send");
                // nothing to send
                continue;
            }
            send_alerts(client, {alertToSend}, rule);
        } catch (const std::exception& e) {
            log_error("CANNOT evaluate rule, because '%s'", e.what());
        }
    }
    mtxAlertConfig.unlock();
    return isEvaluate;
}

void metric_processing(fty::shm::shmMetrics& result, MetricList& cache, mlm_client_t* client)
{
    // process accumulated stream messages
    for (auto& element : result) {
        // std::string topic = element.first;
        // fty_proto_t *bmessage = element.second;

        // process as metric message
        const char* type      = fty_proto_type(element);
        const char* name      = fty_proto_name(element);
        const char* value     = fty_proto_value(element);
        const char* unit      = fty_proto_unit(element);
        uint32_t    ttl       = fty_proto_ttl(element);
        uint64_t    timestamp = fty_proto_aux_number(element, "time", static_cast<uint64_t>(::time(NULL)));

        // TODO: 2016-04-27 ACE: fix it later, when "string" values
        // in the metric would be considered as
        // normal behaviour, but for now it is not supposed to be so
        // -> generated error messages into the log
        char*  end;
        double dvalue = strtod(value, &end);
        if (errno == ERANGE) {
            errno = 0;
            // fty_proto_print (element);
            log_error("%s: can't convert value to double #1, ignore message", name);
            continue;
        } else if (end == value || *end != '\0') {
            // fty_proto_print (element);
            log_error("%s: can't convert value to double #2, ignore message", name);
            continue;
        }

        log_debug("%s: Got message '%s@%s' with value %s", name, type, name, value);

        // Update cache with new value
        MetricInfo m(name, type, unit, dvalue, timestamp, "", ttl);
        cache.addMetric(m);

        // search if this metric is already evaluated and if this metric is evaluate
        std::map<std::string, bool>::iterator found       = evaluateMetrics.find(m.generateTopic());
        bool                                  metricfound = found != evaluateMetrics.end();

        log_debug("Check metric : %s", m.generateTopic().c_str());
        if (metricfound && ManageFtyLog::getInstanceFtylog()->isLogDebug()) {
            log_debug("Metric '%s' is known and %s be evaluated", m.generateTopic().c_str(),
                found->second ? "must" : "will not");
        }

        if (!metricfound || found->second) {
            bool isEvaluate = evaluate_metric(client, m, cache, alertConfiguration);

            // if the metric is evaluate for the first time, add to the list
            if (!metricfound) {
                log_debug("Add %s evaluated metric '%s'", isEvaluate ? " " : "not", m.generateTopic().c_str());
                evaluateMetrics[m.generateTopic()] = isEvaluate;
            }
        }
    }
}

void fty_alert_engine_stream(zsock_t* pipe, void* args)
{
    MetricList cache; // need to track incoming measurements
    char*      name = static_cast<char*>(args);

    mlm_client_t* client = mlm_client_new();
    assert(client);

    zpoller_t* poller = zpoller_new(pipe, mlm_client_msgpipe(client), NULL);
    assert(poller);

    int64_t timeout = fty_get_polling_interval() * 1000;
    zsock_signal(pipe, 0);
    int64_t timeCash = zclock_mono();
    log_info("Actor %s started", name);
    while (!zsys_interrupted) {

        // clear cache every "polling interval" sec
        int64_t timeCurrent = zclock_mono() - timeCash;
        if (timeCurrent >= timeout) {
            fty::shm::shmMetrics result;
            cache.removeOldMetrics();
            timeCash = zclock_mono();
            // Timeout, need to get metrics and update refresh value
            fty::shm::read_metrics(".*", ".*", result);
            log_debug("number of metrics read : %d", result.size());
            timeout = fty_get_polling_interval() * 1000;
            metric_processing(result, cache, client);
        } else {
            timeout = timeout - timeCurrent;
        }

        void* which = zpoller_wait(poller, static_cast<int>(timeout));
        if (which == NULL) {
            if (zpoller_terminated(poller) || zsys_interrupted) {
                log_warning("%s: zpoller_terminated () or zsys_interrupted. Shutting down.", name);
                break;
            }
            if (zpoller_expired(poller)) {
            }
            continue;
        }

        // Drain the queue of pending METRICS stream messages before
        // doing actual work

        // METRICS messages received in this round
        //        std::unordered_map<std::string, fty_proto_t*> stream_messages;
        // Mailbox message received (if any)
        zmsg_t*     zmessage = NULL;
        std::string subject;

        while (which == mlm_client_msgpipe(client)) {
            zmsg_t*     zmsg  = mlm_client_recv(client);
            std::string topic = mlm_client_subject(client);

            if (streq(mlm_client_sender(client), "fty_info_linuxmetrics")) {
                zmsg_destroy(&zmsg);
                continue;
            }

            if (!is_fty_proto(zmsg)) {
                zmessage = zmsg;
                topic    = mlm_client_subject(client);
                break;
            }

            fty_proto_t* bmessage = fty_proto_decode(&zmsg);
            if (!bmessage) {
                log_error("%s: can't decode message with topic %s, ignoring", name, topic.c_str());
                break;
            }

            if (fty_proto_id(bmessage) != FTY_PROTO_METRIC) {
                log_error(
                    "%s: unsupported proto id %d for topic %s, ignoring", name, fty_proto_id(bmessage), topic.c_str());
                fty_proto_destroy(&bmessage);
                break;
            }
            //            auto it = stream_messages.find(topic);
            //            if (it == stream_messages.end()) {
            //                stream_messages.emplace(topic, bmessage);
            //            } else {
            //                // Discard the old METRICS update, we did not manage to process
            //                // it in time.
            //                log_warning("%s: Metrics update '%s' processed too late, discarding", name,
            //                topic.c_str()); fty_proto_destroy(&it->second); it->second = bmessage;
            //            }
            // Check if further messages are pending
            which = zpoller_wait(poller, 0);
        }

        if (which == pipe) {
            zmsg_t* msg = zmsg_recv(pipe);
            char*   cmd = zmsg_popstr(msg);

            if (streq(cmd, "$TERM")) {
                log_info("%s: $TERM received", name);
                zstr_free(&cmd);
                zmsg_destroy(&msg);
                goto exit;
            } else if (streq(cmd, "CONNECT")) {
                log_debug("CONNECT received");
                char* endpoint = zmsg_popstr(msg);
                int   rv       = mlm_client_connect(client, endpoint, 1000, name);
                if (rv == -1)
                    log_error("%s: can't connect to malamute endpoint '%s'", name, endpoint);
                zstr_free(&endpoint);
            } else if (streq(cmd, "PRODUCER")) {
                log_debug("PRODUCER received");
                char* stream = zmsg_popstr(msg);
                int   rv     = mlm_client_set_producer(client, stream);
                if (rv == -1)
                    log_error("%s: can't set producer on stream '%s'", name, stream);
                zstr_free(&stream);
            } else if (streq(cmd, "CONSUMER")) {
                log_debug("CONSUMER received");
                char* stream  = zmsg_popstr(msg);
                char* pattern = zmsg_popstr(msg);
                int   rv      = mlm_client_set_consumer(client, stream, pattern);
                if (rv == -1)
                    log_error("%s: can't set consumer on stream '%s', '%s'", name, stream, pattern);
                zstr_free(&pattern);
                zstr_free(&stream);
            }

            zstr_free(&cmd);
            zmsg_destroy(&msg);
            continue;
        }

        // This agent is a reactive agent, it reacts only on messages
        // and doesn't do anything if there is no messages
        // TODO: probably alert also should be send every XXX seconds,
        // even if no measurements were recieved
        // from the stream  -> metrics
        // but even so we try to decide according what we got, not from where

        if (zmessage) {
            // Here we can have a message with arbitrary topic, but according protocol
            // first frame must be one of the following:
            //  * METRIC_UNAVAILABLE
            char* command = zmsg_popstr(zmessage);
            if (streq(command, "METRICUNAVAILABLE")) {
                char* metrictopic = zmsg_popstr(zmessage);
                if (metrictopic) {
                    check_metrics(client, metrictopic, alertConfiguration);
                } else {
                    log_error("%s: Received stream command '%s', but message has bad format", name, command);
                }
                zstr_free(&metrictopic);
            } else {
                log_error("%s: Unexcepted stream message received with command : %s", name, command);
            }
            zstr_free(&command);
        }
        zmsg_destroy(&zmessage);
    }
exit:
    zpoller_destroy(&poller);
    mlm_client_destroy(&client);
}

void fty_alert_engine_mailbox(zsock_t* pipe, void* args)
{
    char* name = static_cast<char*>(args);

    mlm_client_t* client = mlm_client_new();
    assert(client);

    zpoller_t* poller = zpoller_new(pipe, mlm_client_msgpipe(client), NULL);
    assert(poller);

    uint64_t timeout = 30000;

    zsock_signal(pipe, 0);
    log_info("Actor %s started", name);
    while (!zsys_interrupted) {
        void* which = zpoller_wait(poller, static_cast<int>(timeout));
        if (which == NULL) {
            if (zpoller_terminated(poller) || zsys_interrupted) {
                log_warning("%s: zpoller_terminated () or zsys_interrupted. Shutting down.", name);
                break;
            }
            if (zpoller_expired(poller)) {
            }
            continue;
        }

        if (which == pipe) {
            zmsg_t* msg = zmsg_recv(pipe);
            char*   cmd = zmsg_popstr(msg);
            log_debug("Command : %s", cmd);
            if (streq(cmd, "$TERM")) {
                log_debug("%s: $TERM received", name);
                zstr_free(&cmd);
                zmsg_destroy(&msg);
                goto exit;
            } else if (streq(cmd, "CONNECT")) {
                log_debug("CONNECT received");
                char* endpoint = zmsg_popstr(msg);
                int   rv       = mlm_client_connect(client, endpoint, 1000, name);
                if (rv == -1)
                    log_error("%s: can't connect to malamute endpoint '%s'", name, endpoint);
                zstr_free(&endpoint);
            } else if (streq(cmd, "PRODUCER")) {
                log_debug("PRODUCER received");
                char* stream = zmsg_popstr(msg);
                int   rv     = mlm_client_set_producer(client, stream);
                if (rv == -1)
                    log_error("%s: can't set producer on stream '%s'", name, stream);
                zstr_free(&stream);
            } else if (streq(cmd, "CONFIG")) {
                log_debug("CONFIG received");
                char* filename = zmsg_popstr(msg);
                if (filename) {
                    // Read initial configuration
                    alertConfiguration.setPath(filename);
                    // XXX: somes to subscribe are returned, but not used for now
                    alertConfiguration.readConfiguration();
                } else {
                    log_error("%s: in CONFIG command next frame is missing", name);
                }
                zstr_free(&filename);
            }
            zstr_free(&cmd);
            zmsg_destroy(&msg);
            continue;
        }

        // This agent is a reactive agent, it reacts only on messages
        // and doesn't do anything if there is no messages
        // TODO: probably alert also should be send every XXX seconds,
        // even if no measurements were recieved
        zmsg_t* zmessage = mlm_client_recv(client);
        if (zmessage == NULL) {
            continue;
        }
        // from the mailbox -> rules
        //                  -> request for rule list
        // but even so we try to decide according what we got, not from where
        if (streq(mlm_client_subject(client), RULES_SUBJECT)) {
            log_debug("%s", RULES_SUBJECT);
            // According RFC we expect here a messages
            // with the topic:
            //   * RULES_SUBJECT
            // Here we can have:
            //  * request for list of rules
            //  * get detailed info about the rule
            //  * new/update rule
            //  * touch rule
            char* command = zmsg_popstr(zmessage);
            char* param   = zmsg_popstr(zmessage);
            if (command && param) {
                if (streq(command, "LIST")) {
                    char* rule_class = zmsg_popstr(zmessage);
                    list_rules(client, param, rule_class, alertConfiguration);
                    zstr_free(&rule_class);
                } else if (streq(command, "GET")) {
                    get_rule(client, param, alertConfiguration);
                } else if (streq(command, "ADD")) {
                    if (zmsg_size(zmessage) == 0) {
                        // ADD/json
                        add_rule(client, param, alertConfiguration);
                    } else {
                        // ADD/json/old_name
                        char* param1 = zmsg_popstr(zmessage);
                        update_rule(client, param, param1, alertConfiguration);
                        if (param1)
                            free(param1);
                    }
                } else if (streq(command, "TOUCH")) {
                    touch_rule(client, param, alertConfiguration, true);
                } else if (streq(command, "DELETE")) {
                    log_info("Requested deletion of rule '%s'", param);
                    RuleNameMatcher matcher(param);
                    delete_rules(client, &matcher, alertConfiguration);
                } else if (streq(command, "DELETE_ELEMENT")) {
                    log_info("Requested deletion of rules about element '%s'", param);
                    RuleElementMatcher matcher(param);
                    delete_rules(client, &matcher, alertConfiguration);
                } else {
                    log_error("Received unexpected message to MAILBOX with command '%s'", command);
                }
            }
            zstr_free(&command);
            zstr_free(&param);
        } else {
            char* command = zmsg_popstr(zmessage);
            log_error("%s: Unexcepted mailbox message received with command : %s", name, command);
            zstr_free(&command);
        }
        if (zmessage) {
            zmsg_destroy(&zmessage);
        }
    }
exit:
    zpoller_destroy(&poller);
    mlm_client_destroy(&client);
}

//  --------------------------------------------------------------------------
//  Self test of this class.

// static
char* s_readall(const char* filename)
{
    FILE* fp = fopen(filename, "rt");
    if (!fp)
        return NULL;

    size_t fsize = 0;
    fseek(fp, 0, SEEK_END);
    fsize = static_cast<size_t>(ftell(fp));
    fseek(fp, 0, SEEK_SET);

    char* ret = static_cast<char*>(malloc(fsize * sizeof(char) + 1));
    if (!ret) {
        fclose(fp);
        return NULL;
    }
    memset(static_cast<void*>(ret), '\0', fsize * sizeof(char) + 1);

    size_t r = fread(static_cast<void*>(ret), 1, fsize, fp);
    fclose(fp);
    if (r == fsize)
        return ret;

    free(ret);
    return NULL;
}

static zmsg_t* s_poll_alert(mlm_client_t* consumer, const char* assetName, int timeout_ms = 5000)
{
    assert(consumer);
    zpoller_t* poller = zpoller_new(mlm_client_msgpipe(consumer), NULL);
    assert(poller);

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

void fty_alert_engine_server_test(bool verbose)
{
    setenv("BIOS_LOG_PATTERN", "%D %c [%t] -%-5p- %M (%l) %m%n", 1);
    ManageFtyLog::setInstanceFtylog("fty-alert-engine-server");
    // Note: If your selftest reads SCMed fixture data, please keep it in
    // src/selftest-ro; if your test creates filesystem objects, please
    // do so under src/selftest-rw. They are defined below along with a
    // usecase (asert) to make compilers happy.
    const char* SELFTEST_DIR_RO = "src/selftest-ro";
    const char* SELFTEST_DIR_RW = "src/selftest-rw";
    assert(SELFTEST_DIR_RO);
    assert(SELFTEST_DIR_RW);
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
    assert(r == 0); // to make gcc @ CentOS 7 happy

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
    assert(fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str()) == 0);

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

        assert(zmsg_size(recv) == 3);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "LIST"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "all"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, ""));
        zstr_free(&foo);
        zmsg_destroy(&recv);
    }

    // Test case #2.0: add new rule
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* simplethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/simplethreshold3.rule").c_str());
        assert(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);
    }

    // Test case #2.1: add new rule
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* simplethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/simplethreshold.rule").c_str());
        assert(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);
        // Test case #2.3: existing rule: simplethreshold
        //                 existing rule: simplethreshold2
        //                 update simplethreshold2 with new name simplethreshold
        rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        simplethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/simplethreshold2.rule").c_str());
        assert(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        simplethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/simplethreshold.rule").c_str());
        assert(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        zmsg_addstrf(rule, "%s", "simplethreshold2");
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "ALREADY_EXISTS"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);
        // Test case #5: generate alert - below the treshold
        //        zmsg_t *m = fty_proto_encode_metric (
        //            NULL, ::time (NULL), 0, "abc", "fff", "20", "X");
        assert(fty::shm::write_metric("fff", "abc", "20", "X", wanted_ttl) == 0);
        log_debug("first write ok !");
        //        mlm_client_send (producer, "abc@fff", &m);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());

        assert(is_fty_proto(recv));
        fty_proto_t* brecv = fty_proto_decode(&recv);
        assert(streq(fty_proto_rule(brecv), "simplethreshold"));
        assert(streq(fty_proto_name(brecv), "fff"));
        assert(streq(fty_proto_state(brecv), "ACTIVE"));
        assert(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);

        // Test case #6: generate alert - resolved
        //        m = fty_proto_encode_metric (
        //                NULL, time (NULL), 0, "abc", "fff", "42", "X");
        fty::shm::write_metric("fff", "abc", "42", "X", wanted_ttl);
        //        mlm_client_send (producer, "abc@fff", &m);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());

        assert(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        assert(streq(fty_proto_rule(brecv), "simplethreshold"));
        assert(streq(fty_proto_name(brecv), "fff"));
        assert(streq(fty_proto_state(brecv), "RESOLVED"));
        fty_proto_destroy(&brecv);
        // Test case #6: generate alert - high warning
        //        m = fty_proto_encode_metric (
        //                NULL, time (NULL), 0, "abc", "fff", "52", "X");
        fty::shm::write_metric("fff", "abc", "52", "X", wanted_ttl);
        //        mlm_client_send (producer, "abc@fff", &m);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());

        assert(recv);
        assert(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        assert(brecv);
        assert(streq(fty_proto_rule(brecv), "simplethreshold"));
        assert(streq(fty_proto_name(brecv), "fff"));
        assert(streq(fty_proto_state(brecv), "ACTIVE"));
        assert(streq(fty_proto_severity(brecv), "WARNING"));
        fty_proto_destroy(&brecv);
        // Test case #7: generate alert - high critical
        //        m = fty_proto_encode_metric (
        //                NULL, time (NULL), 0, "abc", "fff", "62", "X");
        fty::shm::write_metric("fff", "abc", "62", "X", wanted_ttl);
        //        mlm_client_send (producer, "abc@fff", &m);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());

        assert(recv);
        assert(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        assert(brecv);
        assert(streq(fty_proto_rule(brecv), "simplethreshold"));
        assert(streq(fty_proto_name(brecv), "fff"));
        assert(streq(fty_proto_state(brecv), "ACTIVE"));
        assert(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);
        // Test case #8: generate alert - resolved again
        //        m = fty_proto_encode_metric (
        //                NULL, time (NULL), 0, "abc", "fff", "42", "X");
        fty::shm::write_metric("fff", "abc", "42", "X", wanted_ttl);
        //        mlm_client_send (producer, "abc@fff", &m);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());

        assert(recv);
        assert(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        assert(brecv);
        assert(streq(fty_proto_rule(brecv), "simplethreshold"));
        assert(streq(fty_proto_name(brecv), "fff"));
        assert(streq(fty_proto_state(brecv), "RESOLVED"));
        fty_proto_destroy(&brecv);
        // Test case #9: generate alert - high again
        //        m = fty_proto_encode_metric (
        //                NULL, time (NULL), 0, "abc", "fff", "62", "X");
        //        mlm_client_send (producer, "abc@fff", &m);
        fty::shm::write_metric("fff", "abc", "62", "X", wanted_ttl);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());

        assert(recv);
        assert(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        assert(brecv);
        assert(streq(fty_proto_rule(brecv), "simplethreshold"));
        assert(streq(fty_proto_name(brecv), "fff"));
        assert(streq(fty_proto_state(brecv), "ACTIVE"));
        assert(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);
        // Test case #11: generate alert - high again
        //        m = fty_proto_encode_metric (
        //                NULL, time (NULL), 0, "abc", "fff", "62", "X");
        //        mlm_client_send (producer, "abc@fff", &m);
        fty::shm::write_metric("fff", "abc", "62", "X", wanted_ttl);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        assert(recv);
        assert(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        assert(brecv);
        assert(streq(fty_proto_rule(brecv), "simplethreshold"));
        assert(streq(fty_proto_name(brecv), "fff"));
        assert(streq(fty_proto_state(brecv), "ACTIVE"));
        assert(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);
        // Test case #12: generate alert - resolved
        //        m = fty_proto_encode_metric (
        //                NULL, time (NULL), 0, "abc", "fff", "42", "X");
        //        mlm_client_send (producer, "abc@fff", &m);
        fty::shm::write_metric("fff", "abc", "42", "X", wanted_ttl);

        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        assert(recv);
        assert(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        assert(brecv);
        assert(streq(fty_proto_rule(brecv), "simplethreshold"));
        assert(streq(fty_proto_name(brecv), "fff"));
        assert(streq(fty_proto_state(brecv), "RESOLVED"));
        fty_proto_destroy(&brecv);
    }

    // Test case #2.2: add new rule with existing name
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* simplethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/simplethreshold.rule").c_str());
        assert(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "ALREADY_EXISTS"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);
    }

    // Test case #2.3: add and delete new rule
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* simplethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/ups.rule").c_str());
        assert(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "DELETE");
        zmsg_addstrf(rule, "%s", "ups");
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "ups"));
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

        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "NO_MATCH"));
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

        assert(zmsg_size(recv) == 6);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "LIST"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "all"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, ""));
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

        assert(zmsg_size(recv) == 3);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "LIST"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "single"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, ""));
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

        assert(zmsg_size(recv) == 4);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "LIST"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "all"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "example class"));
        zstr_free(&foo);
        zmsg_destroy(&recv);
    }

    // Test case #13: segfault on onbattery
    // #13.1 ADD new rule
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* onbattery_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/onbattery-5PX1500-01.rule").c_str());
        assert(onbattery_rule);
        zmsg_addstrf(rule, "%s", onbattery_rule);
        zstr_free(&onbattery_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);
        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
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
        assert(rule);
        zmsg_addstrf(rule, "%s", "ADD");
        char* complexthreshold_rule_lua_error =
            s_readall((str_SELFTEST_DIR_RO + "/testrules/complexthreshold_lua_error.rule").c_str());
        assert(complexthreshold_rule_lua_error);
        zmsg_addstrf(rule, "%s", complexthreshold_rule_lua_error);
        zstr_free(&complexthreshold_rule_lua_error);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);
        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "BAD_LUA"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);
    }

    // Test case #15.1: add Radek's testing rule
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* toohigh_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/too_high-ROZ.ePDU13.rule").c_str());
        assert(toohigh_rule);
        zmsg_addstrf(rule, "%s", toohigh_rule);
        zstr_free(&toohigh_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
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

        assert(recv);
        assert(is_fty_proto(recv));
        fty_proto_t* brecv = fty_proto_decode(&recv);
        assert(brecv);
        assert(streq(fty_proto_rule(brecv), "too_high-ROZ.ePDU13"));
        assert(streq(fty_proto_name(brecv), "ePDU13"));
        assert(streq(fty_proto_state(brecv), "ACTIVE"));
        assert(streq(fty_proto_severity(brecv), "CRITICAL"));
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

        assert(recv);
        assert(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        assert(brecv);
        assert(streq(fty_proto_rule(brecv), "too_high-ROZ.ePDU13"));
        assert(streq(fty_proto_name(brecv), "ePDU13"));
        assert(streq(fty_proto_state(brecv), "ACTIVE"));
        assert(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);
        zmsg_destroy(&recv);
    }

    // Test case #16.1: add new rule, with the trash at the end
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* rule_with_trash = s_readall((str_SELFTEST_DIR_RO + "/testrules/rule_with_trash.rule").c_str());
        assert(rule_with_trash);
        zmsg_addstrf(rule, "%s", rule_with_trash);
        zstr_free(&rule_with_trash);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        // Test case #16.2: add new rule, GET the rule with trash
        zmsg_t* command = zmsg_new();
        zmsg_addstrf(command, "%s", "GET");
        zmsg_addstrf(command, "%s", "rule_with_trash");
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &command);

        recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        std::stringstream           s{foo};
        cxxtools::JsonDeserializer  d{s};
        cxxtools::SerializationInfo si;
        d.deserialize(si);
        assert(si.memberCount() == 1);
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
        assert(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        // 2.
        rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        simplethreshold_rule =
            s_readall((str_SELFTEST_DIR_RO + "/testrules/check_update_threshold_simple2.rule").c_str());
        assert(simplethreshold_rule);
        zmsg_addstrf(rule, "%s", simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        zmsg_addstrf(rule, "%s", "check_update_threshold_simple");
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        // check the result of the operation
        recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
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
        assert(pattern_rule);
        zmsg_addstrf(rule, "%s", pattern_rule);
        zstr_free(&pattern_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
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
        assert(which == NULL);
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
        assert(recv != NULL);
        assert(is_fty_proto(recv));
        fty_proto_t* brecv = fty_proto_decode(&recv);
        assert(streq(fty_proto_rule(brecv), "warranty2"));
        assert(streq(fty_proto_name(brecv), "UPS_pattern_rule"));
        assert(streq(fty_proto_state(brecv), "ACTIVE"));
        assert(streq(fty_proto_severity(brecv), "WARNING"));
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
        assert(recv != NULL);
        assert(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        assert(streq(fty_proto_rule(brecv), "warranty2"));
        assert(streq(fty_proto_name(brecv), "UPS_pattern_rule"));
        assert(streq(fty_proto_state(brecv), "ACTIVE"));
        assert(streq(fty_proto_severity(brecv), "CRITICAL"));
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
        assert(devicethreshold_rule);
        zmsg_addstrf(rule, "%s", devicethreshold_rule);
        zstr_free(&devicethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        //      21.1.2  add existing rule second time: devicethreshold
        log_info("######## Test case #21.1.2 add existing rule second time: devicethreshold");
        rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        devicethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/devicethreshold2.rule").c_str());
        assert(devicethreshold_rule);
        zmsg_addstrf(rule, "%s", devicethreshold_rule);
        zstr_free(&devicethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "ALREADY_EXISTS"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        //      21.2  update existing rule
        rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        devicethreshold_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/devicethreshold2.rule").c_str());
        assert(devicethreshold_rule);
        zmsg_addstrf(rule, "%s", devicethreshold_rule);
        zstr_free(&devicethreshold_rule);
        zmsg_addstrf(rule, "%s", "device_threshold_test"); // name of the rule
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
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
        assert(which == NULL);
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
        assert(simplethreshold_rule);
        zmsg_addstr(rule, simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        log_info(foo);
        assert(streq(foo, "BAD_JSON"));
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
        assert(simplethreshold_rule);
        zmsg_addstr(rule, simplethreshold_rule);
        zstr_free(&simplethreshold_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        log_info(foo);
        assert(streq(foo, "BAD_JSON"));
        zstr_free(&foo);
        zmsg_destroy(&recv);
    }

    // test 23: touch rule, that doesn't exist
    {
        log_info("######## Test case #23: touch rule, that doesn't exist");
        zmsg_t* touch_request = zmsg_new();
        assert(touch_request);
        zmsg_addstr(touch_request, "TOUCH");
        zmsg_addstr(touch_request, "rule_to_touch_doesnt_exists");
        int rv = mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &touch_request);
        assert(rv == 0);

        zmsg_t* recv = mlm_client_recv(ui);
        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "ERROR"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "NOT_FOUND"));
        zstr_free(&foo);
        zmsg_destroy(&recv);
    }

    // test 24: touch rule that exists
    {
        // 24.1 Create a rule we are going to test against
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* rule_to_touch = s_readall((str_SELFTEST_DIR_RO + "/testrules/rule_to_touch.rule").c_str());
        assert(rule_to_touch);
        zmsg_addstrf(rule, "%s", rule_to_touch);
        zstr_free(&rule_to_touch);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        // 24.1.1 there is no any alerts on the rule; send touch request
        zmsg_t* touch_request = zmsg_new();
        assert(touch_request);
        zmsg_addstr(touch_request, "TOUCH");
        zmsg_addstr(touch_request, "rule_to_touch");
        int rv = mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &touch_request);
        assert(rv == 0);

        recv = mlm_client_recv(ui);
        assert(recv);
        assert(zmsg_size(recv) == 1);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        zmsg_destroy(&recv);

        // 24.1.2 No ALERT should be generated/regenerated/closed
        zpoller_t* poller = zpoller_new(mlm_client_msgpipe(consumer), NULL);
        assert(poller);
        void* which = zpoller_wait(poller, polling_value * 2);
        assert(which == NULL);
        if (verbose) {
            log_debug("No alert was sent: SUCCESS");
        }
        zpoller_destroy(&poller);

        // 24.2.1.1 there exists ACTIVE alert (as there were no alerts, lets create one :)); send metric
        //        zmsg_t *m = fty_proto_encode_metric (
        //                NULL, ::time (NULL), 0, "metrictouch", "assettouch", "10", "X");
        //        assert (m);
        //        rv = mlm_client_send (producer, "metrictouch@assettouch", &m);
        fty::shm::write_metric("assettouch", "metrictouch", "10", "X", wanted_ttl);
        assert(rv == 0);

        // 24.2.1.2 receive alert
        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        assert(recv);
        assert(is_fty_proto(recv));
        fty_proto_t* brecv = fty_proto_decode(&recv);
        assert(brecv);
        assert(streq(fty_proto_rule(brecv), "rule_to_touch"));
        assert(streq(fty_proto_name(brecv), "assettouch"));
        assert(streq(fty_proto_state(brecv), "ACTIVE"));
        assert(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);

        // 24.2.2 send touch request
        touch_request = zmsg_new();
        assert(touch_request);
        zmsg_addstr(touch_request, "TOUCH");
        zmsg_addstr(touch_request, "rule_to_touch");
        rv = mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &touch_request);
        assert(rv == 0);

        recv = mlm_client_recv(ui);
        assert(recv);
        assert(zmsg_size(recv) == 1);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        zmsg_destroy(&recv);

        // 24.2.3 the only existing ALERT must be RESOLVED
        poller = zpoller_new(mlm_client_msgpipe(consumer), NULL);
        assert(poller);
        which = zpoller_wait(poller, polling_value * 2);
        assert(which != NULL);
        recv = mlm_client_recv(consumer);
        assert(recv != NULL);
        assert(is_fty_proto(recv));
        if (verbose) {
            brecv = fty_proto_decode(&recv);
            assert(streq(fty_proto_rule(brecv), "rule_to_touch"));
            assert(streq(fty_proto_name(brecv), "assettouch"));
            assert(streq(fty_proto_state(brecv), "RESOLVED"));
            assert(streq(fty_proto_severity(brecv), "CRITICAL"));
            fty_proto_destroy(&brecv);
            log_debug("Alert was sent: SUCCESS");
        }
        zmsg_destroy(&recv);
        zpoller_destroy(&poller);

        // 24.3.1: there exists a RESOLVED alert for this rule; send touch request
        touch_request = zmsg_new();
        assert(touch_request);
        zmsg_addstr(touch_request, "TOUCH");
        zmsg_addstr(touch_request, "rule_to_touch");
        rv = mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &touch_request);
        assert(rv == 0);

        recv = mlm_client_recv(ui);
        assert(recv);
        assert(zmsg_size(recv) == 1);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        zmsg_destroy(&recv);

        // 24.3.2 NO alert should be generated
        poller = zpoller_new(mlm_client_msgpipe(consumer), NULL);
        assert(poller);
        which = zpoller_wait(poller, polling_value * 2);
        assert(which == NULL);
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
        assert(rule_to_touch);
        zmsg_addstrf(rule, "%s", rule_to_touch);
        zstr_free(&rule_to_touch);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        // 25.2 Add Second rule
        rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        rule_to_touch = s_readall((str_SELFTEST_DIR_RO + "/testrules/rule_to_metrictouch2.rule").c_str());
        assert(rule_to_touch);
        zmsg_addstrf(rule, "%s", rule_to_touch);
        zstr_free(&rule_to_touch);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        recv = mlm_client_recv(ui);

        assert(zmsg_size(recv) == 2);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        // 25.3.1 Generate alert on the First rule; send metric
        //        zmsg_t *m = fty_proto_encode_metric (
        //                NULL, ::time (NULL), 0, "metrictouch1", "element1", "100", "X");
        //        assert (m);
        //        int rv = mlm_client_send (producer, "metrictouch1@element1", &m);
        int rv = fty::shm::write_metric("element1", "metrictouch1", "100", "X", wanted_ttl);
        assert(rv == 0);

        // 25.3.2 receive alert
        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        assert(recv);
        assert(is_fty_proto(recv));
        fty_proto_t* brecv = fty_proto_decode(&recv);
        fty_proto_print(brecv);
        assert(brecv);
        assert(streq(fty_proto_rule(brecv), "rule_to_metrictouch1"));
        assert(streq(fty_proto_name(brecv), "element3"));
        assert(streq(fty_proto_state(brecv), "ACTIVE"));
        assert(streq(fty_proto_severity(brecv), "CRITICAL"));
        fty_proto_destroy(&brecv);

        // 25.4.1 Generate alert on the Second rule; send metric
        //        m = fty_proto_encode_metric (
        //                NULL, ::time (NULL), 0, "metrictouch2", "element2", "80", "X");
        //        assert (m);
        //        rv = mlm_client_send (producer, "metrictouch2@element2", &m);
        rv = fty::shm::write_metric("element2", "metrictouch2", "80", "X", wanted_ttl);
        assert(rv == 0);

        // 25.4.2 receive alert
        recv = mlm_client_recv(consumer);

        fty_shm_delete_test_dir();
        fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        assert(recv);
        assert(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        assert(brecv);
        assert(streq(fty_proto_rule(brecv), "rule_to_metrictouch2"));
        assert(streq(fty_proto_name(brecv), "element3"));
        assert(streq(fty_proto_state(brecv), "ACTIVE"));
        assert(streq(fty_proto_severity(brecv), "WARNING"));
        fty_proto_destroy(&brecv);

        // 25.5 Send "metric unavailable"
        // 25.5.1. We need a special client for this
        mlm_client_t* metric_unavailable = mlm_client_new();
        mlm_client_connect(metric_unavailable, endpoint, 1000, "metricunavailable");
        mlm_client_set_producer(metric_unavailable, "_METRICS_UNAVAILABLE");

        // 25.5.2. send UNAVAILABLE metric
        zmsg_t* m_unavailable = zmsg_new();
        assert(m_unavailable);
        zmsg_addstr(m_unavailable, "METRICUNAVAILABLE");
        zmsg_addstr(m_unavailable, "metrictouch1@element1");

        rv = mlm_client_send(metric_unavailable, "metrictouch1@element1", &m_unavailable);
        assert(rv == 0);

        // 25.6 Check that 2 alerts were resolved
        recv = mlm_client_recv(consumer);
        assert(recv);
        assert(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        assert(brecv);
        assert(streq(fty_proto_state(brecv), "RESOLVED"));
        fty_proto_destroy(&brecv);

        recv = mlm_client_recv(consumer);
        assert(recv);
        assert(is_fty_proto(recv));
        brecv = fty_proto_decode(&recv);
        assert(brecv);
        assert(streq(fty_proto_name(brecv), "element3"));
        assert(streq(fty_proto_state(brecv), "RESOLVED"));
        fty_proto_destroy(&brecv);

        // 25.7 clean up
        mlm_client_destroy(&metric_unavailable);
    }

    // # 26 - # 30 : test autoconfig
    mlm_client_t* asset_producer = mlm_client_new();
    assert(asset_producer);
    mlm_client_connect(asset_producer, endpoint, 1000, "asset_producer");
    mlm_client_set_producer(asset_producer, FTY_PROTO_STREAM_ASSETS);

    zactor_t* ag_configurator = zactor_new(autoconfig, static_cast<void*>(const_cast<char*>("test-autoconfig")));
    assert(ag_configurator);
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
        assert (m);
        zhash_destroy (&aux);
        int rv = mlm_client_send (asset_producer, "datacenter.@test", &m);
        assert ( rv == 0 );

        zclock_sleep (20000);

        char *average_humidity = s_readall ((str_SELFTEST_DIR_RW + "/average.humidity@test.rule").c_str ());
        assert (average_humidity);
        char *average_temperature = s_readall ((str_SELFTEST_DIR_RW + "/average.temperature@test.rule").c_str ());
        assert (average_temperature);
        char *realpower_default =  s_readall ((str_SELFTEST_DIR_RW + "/realpower.default@test.rule").c_str ());
        assert (realpower_default);
        char *phase_imbalance = s_readall ((str_SELFTEST_DIR_RW + "/phase_imbalance@test.rule").c_str ());
        assert (phase_imbalance);

        zstr_free (&realpower_default);
        zstr_free (&phase_imbalance);
        zstr_free (&average_humidity);
        zstr_free (&average_temperature);
        // # 26.2 force an alert
        int ttl = wanted_ttl;
//        m = fty_proto_encode_metric (
//            NULL, ::time (NULL), ttl, "average.temperature", "test", "1000", "C");
//        assert (m);
//        rv = mlm_client_send (producer, "average.temperature@test", &m);
        rv = fty::shm::write_metric("test", "average.temperature", "1000", "C", ttl);
        assert ( rv == 0 );

        zmsg_t *recv = mlm_client_recv (consumer);

    fty_shm_delete_test_dir();
    fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        assert (recv);
        assert (is_fty_proto (recv));
        fty_proto_t *brecv = fty_proto_decode (&recv);
        assert (brecv);
        ttl = fty_proto_ttl (brecv);
        assert (ttl != -1);
        assert (streq (fty_proto_rule (brecv), "average.temperature@test"));
        assert (streq (fty_proto_name (brecv), "test"));
        assert (streq (fty_proto_state (brecv), "ACTIVE"));
        assert (streq (fty_proto_severity (brecv), "CRITICAL"));
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
        assert (m);
        zhash_destroy (&aux2);
        int rv = mlm_client_send (asset_producer, "row.@test", &m);
        assert ( rv == 0 );

        zclock_sleep (20000);

        char *average_humidity = s_readall ((str_SELFTEST_DIR_RW + "/average.humidity@test.rule").c_str ());
        assert (average_humidity);
        char *average_temperature = s_readall ((str_SELFTEST_DIR_RW + "/average.temperature@test.rule").c_str ());
        assert (average_temperature);

        zstr_free (&average_humidity);
        zstr_free (&average_temperature);
        // TODO: now inapplicable rules should be deleted in the future
        /* realpower_default =  s_readall ((str_SELFTEST_DIR_RW + "/realpower.default@test.rule").c_str ());
        phase_imbalance = s_readall ((str_SELFTEST_DIR_RW + "/phase.imbalance@test.rule").c_str ());
        assert (realpower_default == NULL && phase_imbalance == NULL); */

        int ttl = wanted_ttl;
        zclock_sleep (3 * ttl);
//        m = fty_proto_encode_metric (
//            NULL, ::time (NULL), ttl, "average.temperature", "test", "1000", "C");
//        assert (m);
//        rv = mlm_client_send (producer, "average.temperature@test", &m);
        fty::shm::write_metric("test", "average.temperature", "1000", "C", ttl);
        assert ( rv == 0 );

        zmsg_t *recv = mlm_client_recv (consumer);

    fty_shm_delete_test_dir();
    fty_shm_set_test_dir(str_SELFTEST_DIR_RW.c_str());
        assert ( recv != NULL );
        assert ( is_fty_proto (recv));
        fty_proto_t *brecv = fty_proto_decode (&recv);
        assert (streq (fty_proto_rule (brecv), "average.temperature@test"));
        assert (streq (fty_proto_name (brecv), "test"));
        assert (streq (fty_proto_state (brecv), "ACTIVE"));
        assert (streq (fty_proto_severity (brecv), "CRITICAL"));
        if (verbose) {
            log_debug ("Alert was sent: SUCCESS");
        }
        fty_proto_destroy (&brecv);
    }
#endif

    // # 28 update the created asset to something completely different, check that alert is resolved
    // and that we deleted old rules and created new

    /* {
     * zhash_t *aux3 = zhash_new ();
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
            assert (streq (fty_proto_name (brecv), "test"));
            assert (streq (fty_proto_state (brecv), "RESOLVED"));
            assert (streq (fty_proto_severity (brecv), "CRITICAL"));
            fty_proto_destroy (&brecv);
            log_debug ("Alert was sent: SUCCESS");
        }
    int ttl3 = fty_proto_ttl (brecv);
    assert (ttl3 != -1);
    zmsg_destroy (&recv);
    zpoller_destroy (&poller);

    char *average_humidity2 = s_readall ((str_SELFTEST_DIR_RO + "/average.humidity@test.rule").c_str ());
    char *average_temperature2 = s_readall ((str_SELFTEST_DIR_RO + "/average.temperature@test.rule").c_str ());
    char *realpower_default2 =  s_readall ((str_SELFTEST_DIR_RO + "/realpower.default@test.rule").c_str ());
    char *phase_imbalance2 = s_readall ((str_SELFTEST_DIR_RO + "/phase.imbalance@test.rule").c_str ());
    assert (average_humidity2 == NULL && average_temperature2 == NULL && realpower_default2 == NULL && phase_imbalance2
    == NULL); zstr_free (&average_humidity2); zstr_free (&average_temperature2); zstr_free (&realpower_default2);
    zstr_free (&phase_imbalance2);

    char *load_1phase = s_readall ((str_SELFTEST_DIR_RO + "/load.input_1phase@test.rule").c_str ());
    assert (load_1phase);
    char *load_3phase = s_readall ((str_SELFTEST_DIR_RO + "/load.input_3phase@test.rule").c_str ());
    assert (load_3phase);
    char *section_load =  s_readall ((str_SELFTEST_DIR_RO + "/section_load@test.rule").c_str ());
    assert (section_load);
    char *phase_imbalance3 = s_readall ((str_SELFTEST_DIR_RO + "/phase.imbalance@test.rule").c_str ());
    assert (phase_imbalance);
    char *voltage_1phase = s_readall ((str_SELFTEST_DIR_RO + "/voltage.input_1phase@test.rule").c_str ());
    assert (voltage_1phase);
    char *voltage_3phase = s_readall ((str_SELFTEST_DIR_RO + "/voltage.input_3phase@test.rule").c_str ());
    assert (voltage_3phase);

    zstr_free (&load_1phase);
    zstr_free (&load_3phase);
    zstr_free (&section_load);
    zstr_free (&phase_imbalance3);
    zstr_free (&voltage_1phase);
    zstr_free (&voltage_3phase);
    } */

    // # 29.1 force the alert for the updated device

    /* {
     * m = fty_proto_encode_metric (
                        NULL, "phase.imbalance", "test", "50", "%", 0);
    assert (m);
    rv = mlm_client_send (producer, "phase.imbalance@test", &m);
    assert ( rv == 0 );

    recv = mlm_client_recv (consumer);
    assert (recv);
    assert (is_fty_proto (recv));
    brecv = fty_proto_decode (&recv);
    assert (brecv);
    int ttl4 = fty_proto_ttl (brecv);
    assert (ttl4 != -1);
    assert (streq (fty_proto_rule (brecv), "phase.imbalance@test.rule"));
    assert (streq (fty_proto_name (brecv), "test"));
    assert (streq (fty_proto_state (brecv), "ACTIVE"));
    assert (streq (fty_proto_severity (brecv), "CRITICAL"));
    fty_proto_destroy (&brecv); */

    // # 29.2 delete the created asset, check that we deleted the rules and all alerts are resolved

    /* m = fty_proto_encode_asset (aux3,
                        "test",
                        FTY_PROTO_ASSET_OP_DELETE,
                        NULL);
    assert (m);
    rv = mlm_client_send (asset_producer, "device.epdu@test", &m);
    assert ( rv == 0 );

    load_1phase = s_readall ((str_SELFTEST_DIR_RO + "/load.input_1phase@test.rule").c_str ());
    load_3phase = s_readall ((str_SELFTEST_DIR_RO + "/load.input_3phase@test.rule").c_str ());
    section_load =  s_readall ((str_SELFTEST_DIR_RO + "/section_load@test.rule").c_str ());
    phase_imbalance3 = s_readall ((str_SELFTEST_DIR_RO + "/phase.imbalance@test.rule").c_str ());
    voltage_1phase = s_readall ((str_SELFTEST_DIR_RO + "/voltage.input_1phase@test.rule").c_str ());
    voltage_3phase = s_readall ((str_SELFTEST_DIR_RO + "/voltage.input_3phase@test.rule").c_str ());

    assert (load_1phase == NULL && load_3phase == NULL && section_load == NULL && phase_imbalance3 == NULL &&
    voltage_1phase == NULL && voltage_3phase == NULL);

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
            assert (streq (fty_proto_name (brecv), "test"));
            assert (streq (fty_proto_state (brecv), "RESOLVED"));
            assert (streq (fty_proto_severity (brecv), "CRITICAL"));
            fty_proto_destroy (&brecv);
            log_debug ("Alert was sent: SUCCESS");
    }
    zmsg_destroy (&recv);
    zpoller_destroy (&poller);
    }
     */
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
        assert(streq(foo, "123456"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "LIST"));
        zstr_free(&foo);
        foo = zmsg_popstr(recv);
        assert(streq(foo, "all"));
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
                assert(fn.compare(template_name) == 0);
                // template content
                foo = zmsg_popstr(recv);
                assert(str.compare(foo) == 0);
                zstr_free(&foo);
                // element list
                foo = zmsg_popstr(recv);
#if 0 // related to 'test' asset created w/ fty-asset (see above)
                if (fn.find ("__row__")!= std::string::npos){
                    log_debug ("template: '%s', devices :'%s'",template_name,foo);
                    assert (streq (foo,"test"));
                }
#endif
                file_counter++;
                zstr_free(&foo);
                zstr_free(&template_name);
            }
        }
        assert(file_counter > 0);
        log_debug("Test #30 : List All templates parse successfully %d files", file_counter);
        zmsg_destroy(&recv);
    }

    // Test case #20 update some rule (type: pattern)
    {
        zmsg_t* rule = zmsg_new();
        zmsg_addstrf(rule, "%s", "ADD");
        char* pattern_rule = s_readall((str_SELFTEST_DIR_RO + "/testrules/pattern.rule").c_str());
        assert(pattern_rule);
        zmsg_addstrf(rule, "%s", pattern_rule);
        zmsg_addstrf(rule, "%s", "warranty2");
        zstr_free(&pattern_rule);
        mlm_client_sendto(ui, "fty-alert-engine", "rfc-evaluator-rules", NULL, 1000, &rule);

        zmsg_t* recv = mlm_client_recv(ui);
        assert(zmsg_size(recv) == 2);
        char* foo = zmsg_popstr(recv);
        assert(streq(foo, "OK"));
        zstr_free(&foo);
        // does not make a sense to call streq on two json documents
        zmsg_destroy(&recv);

        // recieve an alert
        recv = mlm_client_recv(consumer);
        assert(recv != NULL);
        assert(is_fty_proto(recv));
        fty_proto_t* brecv = fty_proto_decode(&recv);
        fty_proto_destroy(&brecv);
    }

    // utf8eq
    {
        static const std::vector<std::string> strings{"ŽlUťOUčKý kůň",
            "\u017dlu\u0165ou\u010dk\xc3\xbd K\u016f\xc5\x88", "Žluťou\u0165ký kůň", "ŽLUťou\u0165Ký kůň",
            "Ka\xcc\x81rol", "K\xc3\xa1rol", "супер test", "\u0441\u0443\u043f\u0435\u0440 Test"};

        assert(utf8eq(strings[0], strings[1]) == 1);
        assert(utf8eq(strings[0], strings[2]) == 0);
        assert(utf8eq(strings[1], strings[2]) == 0);
        assert(utf8eq(strings[2], strings[3]) == 1);
        assert(utf8eq(strings[4], strings[5]) == 0);
        assert(utf8eq(strings[6], strings[7]) == 1);
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
