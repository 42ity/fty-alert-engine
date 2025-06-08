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

#include "autoconfig_info.h"

#include <malamute.h>
#include <list>
#include <vector>
#include <map>
#include <string>
#include <mutex>

#define RULES_SUBJECT "rfc-evaluator-rules"

AutoConfigurationInfo getAssetInfoFromAutoconfig(const std::string& assetName);

void autoconfig(zsock_t* pipe, void* args);

///
///
///

class Autoconfig
{
public:
    Autoconfig() {}
    ~Autoconfig() {
        mlm_client_destroy(&_client);
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
    void onAssetStream(fty_proto_t* proto);
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
    int _timeout{5000}; // ms

    // list of configurable devices (related to alarms)
    std::map<std::string, AutoConfigurationInfo> _configurableDevices;
    std::recursive_mutex _configurableDevicesMutex; // multi-thread access protection

    // list of containers with their friendly names
    std::map<std::string, std::string> _containers; // iname > ename
};
