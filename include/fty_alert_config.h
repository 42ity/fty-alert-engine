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

#ifndef FTY_ALERT_CONFIG_H_INCLUDED
#define FTY_ALERT_CONFIG_H_INCLUDED

#include <string>
#include <vector>
#include <map>
#include <memory>

#ifdef __cplusplus
extern "C" {
#endif

//  @interface
/// main function that start AlertConfig run method
FTY_ALERT_ENGINE_EXPORT void
    fty_alert_config_main (zsock_t *pipe, void* args);

///  Self test of this class
FTY_ALERT_ENGINE_EXPORT void
    fty_alert_config_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

class FullAsset;
class Rule;

class AlertConfig {
    private:
        std::string alert_trigger_mb_name_;
        mlm_client_t *client_;
        std::string template_location_;
        uint64_t timeout_;
        std::string name_;
        // supportive functions
        void listTemplates (std::string corr_id, std::string type);
        std::vector<std::shared_ptr<FullAsset>> getMatchingAssets (std::pair<const std::string,
                std::shared_ptr<Rule>> &rule_template);
        bool ruleMatchAsset (const std::pair<std::string, std::shared_ptr<Rule>> &rule_template,
                std::shared_ptr<FullAsset> asset);
        std::string convertTypeSubType2Name (const char *type, const char *subtype);
        std::map<std::string, std::shared_ptr<Rule>> getAllTemplatesMap ();
        void onAssetCreateCallback (std::shared_ptr<FullAsset> assetptr);
        // // updates are not tracked for alert rule purposes
        // void onAssetUpdateCallback (std::shared_ptr<FullAsset> assetptr);
        void onAssetDeleteCallback (std::shared_ptr<FullAsset> assetptr);
    protected:
        // internal functions
        void handleStreamMessages (zmsg_t **msg);
        void handleMailboxMessages (zmsg_t **msg);
        int handlePipeMessages (zsock_t *pipe);
    public:
        // ctor, dtor
        AlertConfig (const std::string name);
        ~AlertConfig ();
        // execution
        void run (zsock_t *pipe);
};

#endif
