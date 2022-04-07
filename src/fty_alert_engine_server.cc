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

#include "fty_alert_engine_server.h"
#include "alertconfiguration.h"
#include "autoconfig.h"
#include <fty_shm.h>
#include <mutex>
#include <functional>

#include <cxxtools/jsondeserializer.h>
#include <fty_common_json.h>
#include <fty_common_asset_types.h>
#include <regex>

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

// list rules, by type and rule_class
static void list_rules(mlm_client_t* client, const char* type, const char* rule_class, AlertConfiguration& ac)
{
    if (!type) type = "all";
    if (!rule_class) rule_class = "";

    bool typeIsOk = (streq(type, "all")
        || streq(type, "threshold")
        || streq(type, "single")
        || streq(type, "pattern"));

    if (!typeIsOk) {
        // invalid type
        log_warning("type '%s' is invalid", type);
        zmsg_t* reply = zmsg_new();
        zmsg_addstr(reply, "ERROR");
        zmsg_addstr(reply, "INVALID_TYPE");
        mlm_client_sendto(client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
        zmsg_destroy(&reply);
        return;
    }

    std::function<bool(const std::string& s)> filterOnType = [type](const std::string& s)
        { return streq(type, "all") || (s == type); };

    zmsg_t* reply = zmsg_new();
    zmsg_addstr(reply, "LIST");
    zmsg_addstr(reply, type);
    zmsg_addstr(reply, rule_class);

    log_debug("List rules (type: '%s', rule_class: '%s')", type, rule_class);
    log_debug("number of all rules: %zu", ac.size());

    // ac: std::vector<std::pair<RulePtr, std::vector<PureAlert>>>
    std::string rclass{rule_class};
    mtxAlertConfig.lock();
    for (const auto& i : ac) {
        const auto& rule = i.second.first;
        if (filterOnType(rule->whoami()) && (rclass.empty() || rule->rule_class() == rclass)) {
            log_debug("Adding rule '%s'", rule->name().c_str());
            zmsg_addstr(reply, rule->getJsonRule().c_str());
        }
        else {
            log_debug("Skipping rule '%s' (type: '%s', rule_class: '%s')",
                rule->name().c_str(), rule->whoami().c_str(), rule->rule_class().c_str());
        }
    }
    mtxAlertConfig.unlock();

    mlm_client_sendto(client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
    zmsg_destroy(&reply);
}

// list rules (version 2), with more filters defined in a unique json payload
// NOTICE: see fty-alert-flexible rules list mailbox with identical interface

static const char* COMMAND_LIST2 = "LIST2";

static void list_rules2(mlm_client_t* client, const std::string& jsonFilters, AlertConfiguration& ac)
{
    #define RETURN_REPLY_ERROR(reason) { \
        zmsg_t* msg = zmsg_new(); \
        zmsg_addstr(msg, "ERROR"); \
        zmsg_addstr(msg, reason); \
        mlm_client_sendto(client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &msg); \
        zmsg_destroy(&msg); \
        return; \
    }

    struct Filter {
        std::string type;
        std::string rule_class;
        std::string asset_type;
        std::string asset_sub_type;
        std::string in;
        std::string category; // list of, comma sep.
        std::vector<std::string> categoryTokens; // splitted
    };

    // parse rule filter
    Filter filter;
    try {
        cxxtools::SerializationInfo si;
        JSON::readFromString(jsonFilters, si);

        cxxtools::SerializationInfo* p;
        if ((p = si.findMember("type")) && !p->isNull())
            { p->getValue(filter.type); }
        if ((p = si.findMember("rule_class")) && !p->isNull())
            { p->getValue(filter.rule_class); }
        if ((p = si.findMember("asset_type")) && !p->isNull())
            { p->getValue(filter.asset_type); }
        if ((p = si.findMember("asset_sub_type")) && !p->isNull())
            { p->getValue(filter.asset_sub_type); }
        if ((p = si.findMember("in")) && !p->isNull())
            { p->getValue(filter.in); }
        if ((p = si.findMember("category")) && !p->isNull())
            { p->getValue(filter.category); }
    }
    catch (const std::exception& e) {
        log_error("%s exception caught reading filter inputs (e: %s)", COMMAND_LIST2, e.what());
        RETURN_REPLY_ERROR("INVALID_INPUT");
    }

    // filter.type is regular?
    if (!filter.type.empty()) {
        const auto type{filter.type};
        if (type != "all" && type != "threshold" && type != "single" && type != "pattern") {
            RETURN_REPLY_ERROR("INVALID_TYPE");
        }
    }
    // filter.rule_class is regular?
    if (!filter.rule_class.empty()) {
        // free input
    }
    // filter.asset_type is regular?
    if (!filter.asset_type.empty()) {
        auto id = persist::type_to_typeid(filter.asset_type);
        if (id == persist::asset_type::TUNKNOWN) {
            RETURN_REPLY_ERROR("INVALID_ASSET_TYPE");
        }
    }
    // filter.asset_sub_type is regular?
    if (!filter.asset_sub_type.empty()) {
        auto id = persist::subtype_to_subtypeid(filter.asset_sub_type);
        if (id == persist::asset_subtype::SUNKNOWN) {
            RETURN_REPLY_ERROR("INVALID_ASSET_SUB_TYPE");
        }
    }
    // filter.in is regular?
    if (!filter.in.empty()) {
        std::string type; // empty
        if (auto pos = filter.in.rfind("-"); pos != std::string::npos)
            { type = filter.in.substr(0, pos); }
        if (type != "datacenter" && type != "room" && type != "row" && type != "rack") {
            RETURN_REPLY_ERROR("INVALID_IN");
        }
    }
    // filter.category is regular? (free list of tokens, with comma separator)
    filter.categoryTokens.clear();
    if (!filter.category.empty()) {
        // extract tokens in categoryTokens
        std::istringstream stream{filter.category};
        constexpr auto delim{','};
        std::string token;
        while (std::getline(stream, token, delim)) {
            if (!token.empty()) {
                filter.categoryTokens.push_back(token);
            }
        }
        if (filter.categoryTokens.empty()) {
            RETURN_REPLY_ERROR("INVALID_CATEGORY");
        }
    }

    // function to extract asset iname referenced by ruleName
    std::function<std::string(const std::string&)> assetFromRuleName = [](const std::string& ruleName) {
        if (auto pos = ruleName.rfind("@"); pos != std::string::npos)
            { return ruleName.substr(pos + 1); }
        return std::string{};
    };

    // function to extract asset type referenced by ruleName
    std::function<std::string(const std::string&)> assetTypeFromRuleName = [&assetFromRuleName](const std::string& ruleName) {
        std::string asset{assetFromRuleName(ruleName)};
        if (auto pos = asset.rfind("-"); pos != std::string::npos)
            { return asset.substr(0, pos); }
        return std::string{};
    };

    // function to get category tokens for a rule
    // https://confluence-prod.tcc.etn.com/display/PQRELEASE/260005+-+Migrate+Alarms+Settings
    // Note: here we handle *all* rule names, even if not handled by the agent (flexible VS threshold/single/pattern)
    // /!\ category tokens and map **must** be synchronized between:
    // /!\ - fty-alert-engine/src/fty_alert_engine_server.cc categoryTokensFromRuleName()
    // /!\ - fty-alert-flexible/lib/src/flexible_alert.cc categoryTokensFromRuleName()
    std::function<std::vector<std::string>(const std::string&)> categoryTokensFromRuleName = [](const std::string& ruleName) {
        // category tokens
        static constexpr auto T_LOAD{ "load" };
        static constexpr auto T_PHASE_IMBALANCE{ "phase_imbalance" };
        static constexpr auto T_TEMPERATURE{ "temperature" };
        static constexpr auto T_HUMIDITY{ "humidity" };
        static constexpr auto T_EXPIRY{ "expiry" };
        static constexpr auto T_INPUT_CURRENT{ "input_current" };
        static constexpr auto T_OUTPUT_CURRENT{ "output_current" };
        static constexpr auto T_BATTERY{ "battery" };
        static constexpr auto T_INPUT_VOLTAGE{ "input_voltage" };
        static constexpr auto T_OUTPUT_VOLTAGE{ "output_voltage" };
        static constexpr auto T_STS{ "sts" };
        static constexpr auto T_OTHER{ "other" };

        // /!\ **must** sync between fty-alert-engine & fty-alert-flexible
        // category tokens map based on rules name prefix (src/rule_templates/ and fty-nut inlined)
        // define tokens associated to a rule (LIST rules filter)
        // note: an empty vector means 'other'
        static const std::map<std::string, std::vector<std::string>> CAT_TOKENS = {
            { "realpower.default", { T_LOAD } },
            { "phase_imbalance", { T_PHASE_IMBALANCE } },
            { "average.temperature", { T_TEMPERATURE } },
            { "average.humidity", { T_HUMIDITY } },
            { "licensing.expiration", { T_EXPIRY } },
            { "warranty", { T_EXPIRY } },
            { "load.default", { T_LOAD } },
            { "input.L1.current", { T_INPUT_CURRENT } },
            { "input.L2.current", { T_INPUT_CURRENT } },
            { "input.L3.current", { T_INPUT_CURRENT } },
            { "charge.battery", { T_BATTERY} },
            { "runtime.battery", { T_BATTERY } },
            { "voltage.input_1phase", { T_INPUT_VOLTAGE } },
            { "voltage.input_3phase", { T_INPUT_VOLTAGE } },
            { "input.L1.voltage", { T_INPUT_VOLTAGE } },
            { "input.L2.voltage", { T_INPUT_VOLTAGE } },
            { "input.L3.voltage", { T_INPUT_VOLTAGE } },
            { "temperature.default", { T_TEMPERATURE } },
            { "average.temperature", { T_TEMPERATURE } },
            { "realpower.default_1phase", { T_LOAD } },
            { "load.input_1phase", { T_LOAD } },
            { "load.input_3phase", { T_LOAD } },
            { "section_load", { T_LOAD } },
            { "sts-frequency", { T_STS } },
            { "sts-preferred-source", { T_STS } },
            { "sts-voltage", { T_STS } },
            { "ambient.humidity", { T_HUMIDITY } },
            { "ambient.temperature", { T_TEMPERATURE } },
        // enumerated rules (see RULES_1_N)
            { "outlet.group.1.current", { T_OUTPUT_CURRENT } },
            { "outlet.group.1.voltage", { T_OUTPUT_VOLTAGE } },
            { "ambient.1.humidity.status", { T_HUMIDITY } },
            { "ambient.1.temperature.status", { T_TEMPERATURE } },
        }; // CAT_TOKENS

        // enumerated rules redirections
        static const std::vector<std::pair<std::regex, std::string>> RULES_1_N = {
            { std::regex{R"(outlet\.group\.\d{1,4}\.current)"}, "outlet.group.1.current"},
            { std::regex{R"(outlet\.group\.\d{1,4}\.voltage)"}, "outlet.group.1.voltage"},
            { std::regex{R"(ambient\.\d{1,4}\.humidity\.status)"}, "ambient.1.humidity.status"},
            { std::regex{R"(ambient\.\d{1,4}\.temperature\.status)"}, "ambient.1.temperature.status"},
        };

        std::string ruleNamePrefix{ruleName};
        if (auto pos = ruleNamePrefix.rfind("@"); pos != std::string::npos)
            { ruleNamePrefix = ruleNamePrefix.substr(0, pos); }

        auto it = CAT_TOKENS.find(ruleNamePrefix); // search for a rule
        if (it == CAT_TOKENS.end()) { // else, search for a enumerated rule
            for (auto &rex : RULES_1_N) {
                std::smatch m;
                if (std::regex_match(ruleNamePrefix, m, rex.first)) {
                    it = CAT_TOKENS.find(rex.second); // redirect search
                    break;
                }
            }
        }
        if (it == CAT_TOKENS.end()) {
            log_debug("key '%s' not found in CAT_TOKENS map", ruleNamePrefix.c_str());
            return std::vector<std::string>({ T_OTHER }); // not found
        }

        if (it->second.empty()) { // empty means 'other'
            return std::vector<std::string>({ T_OTHER });
        }
        return it->second;
    };

    // rule match filter? returns true if yes
    std::function<bool(const RulePtr&)> match =
    [&filter, &assetFromRuleName, &assetTypeFromRuleName, &categoryTokensFromRuleName](const RulePtr& rule) {
        // type (rule->whoami() in ["threshold", "single", "pattern", ...])
        if (!filter.type.empty()) {
            if ((filter.type != "all") && (filter.type != rule->whoami()))
                { return false; }
        }
        // rule_class (deprecated?)
        if (!filter.rule_class.empty()) {
            if (filter.rule_class != rule->rule_class())
                { return false; }
        }
        // asset_type
        if (!filter.asset_type.empty()) {
            std::string type{assetTypeFromRuleName(rule->name())};
            if (filter.asset_type == "device") { // 'device' exception
                auto id = persist::subtype_to_subtypeid(type);
                if (id == persist::asset_subtype::SUNKNOWN)
                    { return false; } // 'type' is not a device
            }
            else if (filter.asset_type != type)
                { return false; }
        }
        // asset_sub_type
        if (!filter.asset_sub_type.empty()) {
            std::string type{assetTypeFromRuleName(rule->name())};
            if (filter.asset_sub_type != type)
                { return false; }
        }
        // in (location)
        if (!filter.in.empty()) {
            std::string asset{assetFromRuleName(rule->name())};
            AutoConfigurationInfo info = getAssetInfoFromAutoconfig(asset);
            auto it = std::find(info.locations.begin(), info.locations.end(), filter.in);
            if (it == info.locations.end())
                { return false; }
        }
        // category
        if (!filter.categoryTokens.empty()) {
            std::vector<std::string> ruleTokens = categoryTokensFromRuleName(rule->name());
            for (auto& token : filter.categoryTokens) {
                auto it = std::find(ruleTokens.begin(), ruleTokens.end(), token);
                if (it == ruleTokens.end())
                    { return false; }
            }
        }

        return true; // match
    };

    zmsg_t* reply = zmsg_new();
    zmsg_addstr(reply, COMMAND_LIST2);
    zmsg_addstr(reply, jsonFilters.c_str());

    log_debug("List rules (%s, jsonFilters: '%s')", COMMAND_LIST2, jsonFilters.c_str());
    log_debug("number of rules: %zu", ac.size());

    // ac: std::vector<std::pair<RulePtr, std::vector<PureAlert>>>
    mtxAlertConfig.lock();
    for (const auto& i : ac) {
        const auto& rule = i.second.first;
        if (match(rule)) {
            log_debug("%s add rule '%s'", COMMAND_LIST2, rule->name().c_str());
            zmsg_addstr(reply, rule->getJsonRule().c_str());
        }
        else {
            log_debug("%s skip rule '%s'", COMMAND_LIST2, rule->name().c_str());
        }
    }
    mtxAlertConfig.unlock();

    mlm_client_sendto(client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
    zmsg_destroy(&reply);
    #undef RETURN_REPLY_ERROR
}

static void get_rule(mlm_client_t* client, const char* name, AlertConfiguration& ac)
{
    assert(name != NULL);
    zmsg_t* reply = zmsg_new();
    bool    found = false;

    log_debug("number of all rules = '%zu'", ac.size());

    mtxAlertConfig.lock();
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
        log_debug("rule not found (%s)", name);
        zmsg_addstr(reply, "ERROR");
        zmsg_addstr(reply, "NOT_FOUND");
    }

    mlm_client_sendto(client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
    zmsg_destroy(&reply);
}

// XXX: Store the actions as zlist_t internally to avoid useless copying
static zlist_t* makeActionList(const std::vector<std::string>& actions)
{
    zlist_t* res = zlist_new();
    for (const auto& oneAction : actions) {
        zlist_append(res, const_cast<char*>(oneAction.c_str()));
    }
    return res;
}

static void send_alerts(mlm_client_t* client, const std::vector<PureAlert>& alertsToSend, const std::string& rule_name)
{
    for (const auto& alert : alertsToSend) {
        // Asset id is missing in the rule name for warranty alarms
        std::string fullRuleName = rule_name;
        if (streq("warranty", fullRuleName.c_str())) {
            fullRuleName += "@" + alert._element;
        }

        zlist_t* actions = makeActionList(alert._actions);
        zmsg_t*  msg = fty_proto_encode_alert(NULL, static_cast<uint64_t>(::time(NULL)),
            static_cast<uint32_t>(alert._ttl), fullRuleName.c_str(), alert._element.c_str(), alert._status.c_str(),
            alert._severity.c_str(), alert._description.c_str(), actions);
        zlist_destroy(&actions);

        if (msg) {
            std::string atopic = rule_name + "/" + alert._severity + "@" + alert._element;
            mlm_client_send(client, atopic.c_str(), &msg);
            log_info("Send Alert for %s with state %s and severity %s", fullRuleName.c_str(), alert._status.c_str(),
                alert._severity.c_str());
        }
        zmsg_destroy(&msg);
    }
}

static void send_alerts(mlm_client_t* client, const std::vector<PureAlert>& alertsToSend, const RulePtr& rule)
{
    send_alerts(client, alertsToSend, rule->name());
}

static void add_rule(mlm_client_t* client, const char* json_representation, AlertConfiguration& ac)
{
    std::istringstream           f(json_representation);
    std::set<std::string>        newSubjectsToSubscribe;
    std::vector<PureAlert>       alertsToSend;
    AlertConfiguration::iterator new_rule_it;

    mtxAlertConfig.lock();
    int rv = ac.addRule(f, newSubjectsToSubscribe, alertsToSend, new_rule_it);
    mtxAlertConfig.unlock();

    // ZZZ rework/factorize that switch
    zmsg_t* reply = zmsg_new();

    bool sendAlerts = false;
    switch (rv) {
        case 0: { // rule was created succesfully
            log_debug("rule added correctly");
            zmsg_addstr(reply, "OK");
            zmsg_addstr(reply, json_representation);
            // send updated alert
            sendAlerts = true;
            break;
        }
        case -2: { // rule exists
            log_debug("rule already exists");
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "ALREADY_EXISTS");
            break;
        }
        case -5: { // error during the rule creation (lua)
            log_warning("rule has bad lua");
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "BAD_LUA");
            break;
        }
        case -6: { // error during the rule creation (lua)
            log_error("internal error");
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "Internal error - operating with storage/disk failed.");
            break;
        }
        case -100: { // PQSWMBT-3723 rule can't be directly instantiated
            log_debug("rule can't be directly instantiated");
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "Rule can't be directly instantiated.");
            break;
        }
        case -101: { // PQSWMBT-4921 Xphase rule can be *only* instantiated for Xphase device
            log_debug ("Xphase rule can't be instantiated");
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "Xphase rule can't be instantiated.");
            break;
        }
        default: { // error during the rule creation
            log_warning("default, bad or unrecognized json for rule %s", json_representation);
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "BAD_JSON");
            break;
        }
    }

    // send the reply
    int r = mlm_client_sendto(
        client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
    zmsg_destroy(&reply);
    if (r != 0) {
        log_error("mlm_client_sendto() %s failed", mlm_client_sender(client));
    }

    if (sendAlerts) {
        send_alerts(client, alertsToSend, new_rule_it->second.first);
    }
}

static void update_rule(mlm_client_t* client, const char* json_representation, const char* rule_name, AlertConfiguration& ac)
{
    std::istringstream           f(json_representation);
    std::set<std::string>        newSubjectsToSubscribe;
    std::vector<PureAlert>       alertsToSend;
    AlertConfiguration::iterator new_rule_it;

    mtxAlertConfig.lock();
    int rv = -7;
    if (rule_name) {
        rv = ac.updateRule(f, rule_name, newSubjectsToSubscribe, alertsToSend, new_rule_it);
    }
    mtxAlertConfig.unlock();

    zmsg_t* reply = zmsg_new();

    bool sendAlerts = false;
    switch (rv) {
        case 0: { // rule was updated succesfully
            log_debug("rule updated");
            zmsg_addstr(reply, "OK");
            zmsg_addstr(reply, json_representation);
            // send updated alert
            sendAlerts = true;
            break;
        }
        case -2: { // rule doesn't exist
            log_debug("rule not found");
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "NOT_FOUND");
            break;
        }
        case -3: { // rule with new rule name already exists
            log_debug("new rule name already exists");
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "ALREADY_EXISTS");
            break;
        }
        case -5: { // error during the rule creation (lua)
            log_warning("rule has incorrect lua");
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "BAD_LUA");
            break;
        }
        case -6: { // error during the rule update
            log_error("internal error");
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "Internal error - operating with storage/disk failed.");
            break;
        }
        default: { // error during the rule update
            log_warning("bad json default for %s", json_representation);
            zmsg_addstr(reply, "ERROR");
            zmsg_addstr(reply, "BAD_JSON");
            break;
        }
    }

    // send the reply
    int r = mlm_client_sendto(
        client, mlm_client_sender(client), RULES_SUBJECT, mlm_client_tracker(client), 1000, &reply);
    zmsg_destroy(&reply);
    if (r != 0) {
        log_error("mlm_client_sendto() %s failed", mlm_client_sender(client));
    }

    if (sendAlerts) {
        send_alerts(client, alertsToSend, new_rule_it->second.first);
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
    zmsg_destroy(&reply);
    mtxAlertConfig.unlock();
}

static void touch_rule(mlm_client_t* client, const char* rule_name, AlertConfiguration& ac, bool send_reply)
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
                zmsg_destroy(&reply);
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
                zmsg_destroy(&reply);
            }
            // send updated alert
            send_alerts(client, alertsToSend, rule_name); // TODO third parameter
            return;
        }
    }
}

static void check_metrics(mlm_client_t* client, const char* metric_topic, AlertConfiguration& ac)
{
    const std::vector<std::string> rules_of_metric = ac.getRulesByMetric(metric_topic);
    for (const auto& rulename : rules_of_metric) {
        touch_rule(client, rulename.c_str(), ac, false);
    }
}

static bool evaluate_metric(mlm_client_t* client, const MetricInfo& triggeringMetric, const MetricList& knownMetricValues,
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

//    log_debug(" ### evaluate topic '%s' (rules size: %zu)", sTopic.c_str(), rules_of_metric.size());

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
                    // clang-format off
                    alertToSend._description =
                        std::string("{\"key\" : \"TRANSLATE_LUA (Warranty on {{asset}} expired {{days}} days ago.)\", ") +
                        "\"variables\" : { \"asset\" : { \"value\" : \"\", \"assetLink\" : \"" +
                        triggeringMetric.getElementName() + "\" }, \"days\" : \"" + std::to_string(remaining_days) + "\"} }";
                    // clang-format on
                } else if (alertToSend._description == "{\"key\":\"TRANSLATE_LUA (Warranty expires in)\"}") {
                    // Style note: do not break long translated lines, that would break their parser
                    // clang-format off
                    alertToSend._description =
                            std::string("{\"key\" : \"TRANSLATE_LUA (Warranty on {{asset}} expires in less than {{days}} days.)\", ") +
                                        "\"variables\" : { \"asset\" : { \"value\" : \"\", \"assetLink\" : \"" +
                                        triggeringMetric.getElementName() + "\" }, \"days\" : \"" + std::to_string(remaining_days) + "\"} }";
                    // clang-format on
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

static void metric_processing(fty::shm::shmMetrics& result, MetricList& cache, mlm_client_t* client)
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

//        log_debug("%s: Got message '%s@%s' with value %s", name, type, name, value);

        // Update cache with new value
        MetricInfo m(name, type, unit, dvalue, timestamp, "", ttl);
        cache.addMetric(m);

        // search if this metric is already evaluated and if this metric is evaluate
        std::map<std::string, bool>::iterator found       = evaluateMetrics.find(m.generateTopic());
        bool                                  metricfound = found != evaluateMetrics.end();

//        log_debug("Check metric : %s", m.generateTopic().c_str());
        if (metricfound && ManageFtyLog::getInstanceFtylog()->isLogDebug()) {
//            log_debug("Metric '%s' is known and %s be evaluated", m.generateTopic().c_str(),
//                found->second ? "must" : "will not");
        }

        if (!metricfound || found->second) {
            bool isEvaluate = evaluate_metric(client, m, cache, alertConfiguration);

            // if the metric is evaluate for the first time, add to the list
            if (!metricfound) {
//                log_debug("Add %s evaluated metric '%s'", isEvaluate ? " " : "not", m.generateTopic().c_str());
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

    zsock_signal(pipe, 0);
    log_info("Actor %s started", name);

    int64_t timeout = fty_get_polling_interval() * 1000; // ms
    int64_t timeCash = zclock_mono();

    while (!zsys_interrupted) {

        // clear cache every "polling interval" sec
        int64_t timeCurrent = zclock_mono() - timeCash;
        if (timeCurrent >= timeout) {
            fty::shm::shmMetrics result;
            cache.removeOldMetrics();
            timeCash = zclock_mono();
            // Timeout, need to get metrics and update refresh value
            fty::shm::read_metrics(".*", ".*", result);
            log_debug("number of metrics read : %zu", result.size());
            timeout = fty_get_polling_interval() * 1000;
            metric_processing(result, cache, client);
        }
        else {
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

            if (!fty_proto_is(zmsg)) {
                zmsg_destroy(&zmessage);
                zmessage = zmsg;
                topic    = mlm_client_subject(client);
                break;
            }

            fty_proto_t* bmessage = fty_proto_decode(&zmsg);
            zmsg_destroy(&zmsg);

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

            fty_proto_destroy(&bmessage);

            which = zpoller_wait(poller, 0);
        }

        if (which == pipe) {
            zmsg_destroy(&zmessage); // ignored here until continue

            zmsg_t* msg = zmsg_recv(pipe);
            char*   cmd = zmsg_popstr(msg);

            if (streq(cmd, "$TERM")) {
                log_info("%s: $TERM received", name);
                zstr_free(&cmd);
                zmsg_destroy(&msg);
                goto exit;
            }

            if (streq(cmd, "CONNECT")) {
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
    log_info("Actor %s ended", name);
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
                break;
            }

            if (streq(cmd, "CONNECT")) {
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
        if (!zmessage) {
            continue;
        }

        // from the mailbox -> rules
        //                  -> request for rule list
        // but even so we try to decide according what we got, not from where
        if (streq(mlm_client_subject(client), RULES_SUBJECT)) {
            // According RFC we expect here a messages
            // with the topic:
            //   * RULES_SUBJECT
            // Here we can have:
            //  * request for list of rules
            //  * get detailed info about the rule
            //  * new/update rule
            //  * touch rule
            const char* sender = mlm_client_sender(client);
            char* command = zmsg_popstr(zmessage);
            char* param0  = zmsg_popstr(zmessage);
            log_debug("IN-MAILBOX from %s: subject: %s, cmd: %s, param0: %s", sender, RULES_SUBJECT, command, param0);

            if (command && param0) {
                if (streq(command, "LIST")) {
                    // request: LIST/type/rule_class
                    // reply: LIST/type/rule_class/rule1/.../ruleN
                    // reply: ERROR/reason
                    char* param1 = zmsg_popstr(zmessage);
                    list_rules(client, param0, param1, alertConfiguration);
                    zstr_free(&param1);
                }
                else if (streq(command, COMMAND_LIST2)) { // LIST (version 2)
                    // request: <command>/jsonPayload
                    // reply: <command>/jsonPayload/rule1/.../ruleN
                    // reply: ERROR/reason
                    list_rules2(client, param0, alertConfiguration);
                }
                else if (streq(command, "GET")) {
                    get_rule(client, param0, alertConfiguration);
                }
                else if (streq(command, "ADD")) {
                    if (zmsg_size(zmessage) == 0) {
                        // ADD/json
                        add_rule(client, param0, alertConfiguration);
                    }
                    else {
                        // ADD/json/old_name
                        char* param1 = zmsg_popstr(zmessage);
                        update_rule(client, param0, param1, alertConfiguration);
                        zstr_free(&param1);
                    }
                }
                else if (streq(command, "TOUCH")) {
                    touch_rule(client, param0, alertConfiguration, true);
                }
                else if (streq(command, "DELETE")) {
                    log_info("Requested deletion of rule '%s'", param0);
                    RuleNameMatcher matcher(param0);
                    delete_rules(client, &matcher, alertConfiguration);
                }
                else if (streq(command, "DELETE_ELEMENT")) {
                    log_info("Requested deletion of rules about element '%s'", param0);
                    RuleElementMatcher matcher(param0);
                    delete_rules(client, &matcher, alertConfiguration);
                }
                else {
                    log_error("Received unexpected message to MAILBOX with command '%s'", command);
                }
            }
            zstr_free(&command);
            zstr_free(&param0);
        } else {
            char* command = zmsg_popstr(zmessage);
            log_error("%s: Unexcepted mailbox message received with command : %s", name, command);
            zstr_free(&command);
        }
        zmsg_destroy(&zmessage);
    }

    log_info("Actor %s ended", name);
    zpoller_destroy(&poller);
    mlm_client_destroy(&client);
}

//  --------------------------------------------------------------------------
//  Self test of this class.

//static (required for tests)
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
