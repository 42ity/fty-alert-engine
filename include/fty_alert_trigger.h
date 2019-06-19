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

#ifndef FTY_ALERT_TRIGGER_H_INCLUDED
#define FTY_ALERT_TRIGGER_H_INCLUDED

#include <string>
#include <map>
#include <mutex>
#include <memory>
#include <vector>
#include <unordered_set>
#include <fty_shm.h>

#ifdef __cplusplus
extern "C" {
#endif

//  @interface
//  Create a new fty_alert_trigger
FTY_ALERT_ENGINE_EXPORT fty_alert_trigger_t *
    fty_alert_trigger_new (void);

//  Destroy the fty_alert_trigger
FTY_ALERT_ENGINE_EXPORT void
    fty_alert_trigger_destroy (fty_alert_trigger_t **self_p);

//  Main function of the fty_alert_trigger mailbox
FTY_ALERT_ENGINE_EXPORT void
    fty_alert_trigger_mailbox_main (zsock_t *pipe, void* args);

//  Main function of the fty_alert_trigger stream
FTY_ALERT_ENGINE_EXPORT void
    fty_alert_trigger_stream_main (zsock_t *pipe, void* args);

//  Self test of this class
FTY_ALERT_ENGINE_EXPORT void
    fty_alert_trigger_test (bool verbose);

//  @end

#ifdef __cplusplus
}
#endif

class Rule;
template <typename A, typename B> class ObservedGenericDatabase;
class RuleMatcher;

class AlertTrigger {
    private:
        using RuleDatabase = ObservedGenericDatabase<std::string, std::shared_ptr<Rule>>;
        using RuleSPtr = std::shared_ptr<Rule>;
        /// rule cache
        static RuleDatabase known_rules_;
        static std::mutex known_rules_mutex_;
        // metrics cache
        static std::vector<fty_proto_t *> streamed_metrics_;
        static std::unordered_set<std::string> unavailable_metrics_;
        static std::mutex stream_metrics_mutex_;
        // other variables
        mlm_client_t *client_;
        mlm_client_t *client_mb_sender_;
        zpoller_t *client_mb_sender_poller_;
        std::string rule_location_;
        static int64_t timeout_;
        std::string name_;
        std::string alert_list_mb_name_;
        // supportive functions
        void evaluateAlarmsForTriggers (fty::shm::shmMetrics &shm_metrics);
        void deleteRules (std::string corr_id, RuleMatcher *matcher);
        void touchRule (std::string corr_id, std::string name);
        void updateRule (std::string corr_id, std::string json, std::string old_name);
        void addRule (std::string corr_id, std::string json);
        void getRule (std::string corr_id, std::string name);
        void listRules (std::string corr_id, std::string type, std::string ruleclass);
        void setTimeout (int64_t timeout) { timeout_ = timeout; }
        void loadFromPersistence ();
        // callbacks for rule database
        void onRuleCreateCallback (RuleSPtr ruleptr);
        void onRuleUpdateCallback (RuleSPtr ruleptr);
        void onRuleDeleteCallback (RuleSPtr ruleptr);
    protected:
        // internal functions
        void handleStreamMessages ();
        void handleMailboxMessages ();
        int handlePipeMessages (zsock_t *pipe);
    public:
        // ctor, dtor
        AlertTrigger (const std::string name);
        ~AlertTrigger ();
        // execution
        void runStream (zsock_t *pipe);
        void runMailbox (zsock_t *pipe);
        // setter for static resources
        void initCallbacks ();
};

#endif
