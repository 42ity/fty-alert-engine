/*  =========================================================================
    autoconfig - Autoconfig

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

#pragma once

#include "utils.h"

#include <fty_proto.h>

#include <malamute.h>
#include <list>
#include <vector>
#include <map>
#include <string>
#include <mutex>

#define RULES_SUBJECT "rfc-evaluator-rules"

struct AutoConfigurationInfo
{
    std::string type;
    std::string subtype;
    std::string operation;
    std::string update_ts;
    uint64_t date{0}; // *must* be 0
    bool configured{false}; // *must* be false

    std::map<std::string, std::string> attributes; // <key,value>
    std::vector<std::string> locations; // inames (dc, room, ...)

    // not initialized?
    bool empty() const
    {
        return type.empty();
    }

    // ext. attribute accessor
    std::string getAttr(const std::string& attrName, const std::string& defValue = "") const
    {
        const auto it = attributes.find(attrName);
        return (it != attributes.end()) ? it->second : defValue;
    }

    // dbg, dump with filter on ext. attributes
    std::string dump(const std::vector<std::string>& attrFilter) const
    {
        if (empty()) { return "<empty>"; } // not initialized

        std::string s{type + "(" + subtype + ")/" + operation};

        for (const auto& it : attributes) {
            const std::string key{it.first};
            const std::string value{it.second};

            if (!attrFilter.empty()) {
                bool found{false};
                for (const auto& attr : attrFilter) {
                    if (key.find(attr) != std::string::npos)
                        { found = true; break; }
                }
                if (!found) { continue; }
            }

            s += "," + key + "=" + value;
        }
        return s;
    }

    // dbg, full dump
    std::string dump() const { return dump({}); }

    bool operator == (fty_proto_t* message) const
    {
        bool b;

        b = (operation == fty_proto_operation(message))
            && (type == fty_proto_aux_string(message, FTY_PROTO_ASSET_TYPE, ""))
            && (subtype == fty_proto_aux_string(message, FTY_PROTO_ASSET_SUBTYPE, ""));
        if (!b) { return false; }

        // self is implicitly active, so we have to test it
        b = streq(fty_proto_aux_string(message, FTY_PROTO_ASSET_STATUS, "active"), "active");
        if (!b) { return false; }

        // test all ext attributes
        std::map<std::string, std::string> msg_attributes = utils::zhash_to_map(fty_proto_ext(message));
        return attributes.size() == msg_attributes.size()
               && std::equal(attributes.begin(), attributes.end(), msg_attributes.begin());
    };
};

AutoConfigurationInfo getAssetInfoFromAutoconfig(const std::string& assetName);

void autoconfig(zsock_t* pipe, void* args);

class Autoconfig
{
public:
    Autoconfig() {}
    ~Autoconfig() {
        mlm_client_destroy(&_client);
        mlm_client_destroy(&_clientSender);
    }

    static std::string StateFile;       //!< pathfile where Autoconfig state is saved
    static std::string StateFilePath;   //!< path to dir where Autoconfig state is saved
    static std::string RuleFilePath;    //!< path to dir where Autoconfig rule templates are saved
    static std::string AlertEngineName; //!< fty-alert-engine mlm client address

    void run(zsock_t* pipe, const std::string& name);

    std::string getEname(const std::string& assetName) const;
    AutoConfigurationInfo configurableDevicesGet(const std::string& assetName);

private: // methods
    void main(zsock_t* pipe, const std::string& name);
    void onSend(fty_proto_t* message);
    void onPoll();

    void configurableDevicesAdd(const std::string& assetName, const AutoConfigurationInfo& info);
    void configurableDevicesRemove(const std::string& assetName);

    void setPollingInterval();
    void saveState();
    void loadState();

    std::list<std::string> getAssetsThatMatchTemplate(const std::string& template_name);
    void listTemplates(const char* correlation_id, const char* filter);

private: // properties
    mlm_client_t* _client{nullptr};
    mlm_client_t* _clientSender{nullptr};
    int           _timeout{5000}; // ms

    // list of configurable devices (related to alarms)
    std::map<std::string, AutoConfigurationInfo> _configurableDevices;
    std::recursive_mutex _configurableDevicesMutex; // multi-thread access protection

    // list of containers with their friendly names
    std::map<std::string, std::string> _containers; // iname > ename
};
