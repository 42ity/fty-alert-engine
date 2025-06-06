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

#include "autoconfig.h"
#include "templateruleconfigurator.h"

#include <fty_log.h>
#include <fty_common_asset_types.h>
#include <fty_common_json.h>
#include <cxxtools/serializationinfo.h>
#include <filesystem>

std::string Autoconfig::StateFilePath;
std::string Autoconfig::RuleFilePath;
std::string Autoconfig::StateFile;
std::string Autoconfig::AlertEngineName;

inline void operator <<= (cxxtools::SerializationInfo& si, const AutoConfigurationInfo& info)
{
    si.addMember("type") <<= info.type;
    si.addMember("subtype") <<= info.subtype;
    si.addMember("operation") <<= info.operation;
    si.addMember("configured") <<= info.configured;
    si.addMember("date") <<= std::to_string(info.date);
    si.addMember("attributes") <<= info.attributes;
    si.addMember("locations") <<= info.locations;
}

inline void operator >>= (const cxxtools::SerializationInfo& si, AutoConfigurationInfo& info)
{
    try {
        std::string temp, dateStr;

        si.getMember("configured") >>= info.configured;
        si.getMember("type") >>= temp; // ignored!?
        si.getMember("subtype") >>= temp; // ignored!?
        si.getMember("operation") >>= temp; // ignored!?
        si.getMember("date") >>= dateStr;
        si.getMember("attributes") >>= info.attributes;
        si.getMember("locations") >>= info.locations;

        info.date = static_cast<uint64_t>(std::stoi(dateStr));
    }
    catch (const std::exception& e) {
        log_error("AutoConfigurationInfo::parse failed (e: %s)", e.what());
    }
}

// multi-thread access guard for _configurableDevices map
#define ConfigurableDevices_GUARD \
    std::lock_guard<std::recursive_mutex> guard(_configurableDevicesMutex)

void Autoconfig::main(zsock_t* pipe, const std::string& name_)
{
    const char* name = name_.c_str();

    if (_client) { mlm_client_destroy(&_client); }

    _client = mlm_client_new();
    if (!_client) {
        log_error("mlm_client_new() failed");
        mlm_client_destroy(&_client);
        return;
    }

    zpoller_t* poller = zpoller_new(pipe, mlm_client_msgpipe(_client), NULL);
    if (!poller) {
        log_error("zpoller_new() failed");
        mlm_client_destroy(&_client);
        return;
    }

    log_info("%s started", name);
    zsock_signal(pipe, 0);

    int64_t timestamp = 0;

    while (!zsys_interrupted) {

        void* which = zpoller_wait(poller, _timeout);

        if (which == NULL) {
            if (zpoller_terminated(poller) || zsys_interrupted) {
                break;
            }
        }

        if ((zclock_mono() - timestamp) >= _timeout) {
            onPoll();
            timestamp = zclock_mono();
        }

        // Rx on main socket
        if (which == pipe) {
            zmsg_t* msg = zmsg_recv(pipe);
            char* cmd = zmsg_popstr(msg);
            bool term{false};

            if (!cmd) {
                log_error("%s: cmd is missing", name);
            }
            else if (streq(cmd, "$TERM")) {
                log_debug("%s: $TERM received", name);
                term = true;
            }
            else if (streq(cmd, "TEMPLATES_DIR")) {
                char* dirname = zmsg_popstr(msg);
                log_debug("TEMPLATES_DIR received (%s)", dirname);
                if (dirname) {
                    Autoconfig::RuleFilePath = std::string(dirname);
                }
                else {
                    log_error("%s: %s frame is missing", name, cmd);
                }
                zstr_free(&dirname);
            }
            else if (streq(cmd, "CONFIG")) {
                char* dirname = zmsg_popstr(msg);
                log_debug("CONFIG received (%s)", dirname);
                if (dirname) {
                    Autoconfig::StateFilePath = std::string(dirname);
                    Autoconfig::StateFile = Autoconfig::StateFilePath + "/state";
                    loadState();
                }
                else {
                    log_error("%s: %s frame is missing", name, cmd);
                }
                zstr_free(&dirname);
            }
            else if (streq(cmd, "CONNECT")) {
                char* endpoint = zmsg_popstr(msg);
                log_debug("CONNECT received (%s)", endpoint);
                int r = mlm_client_connect(_client, endpoint, 1000, name);
                if (r != 0) {
                    log_error("%s: can't connect to malamute endpoint '%s'", name, endpoint);
                }
                zstr_free(&endpoint);
            }
            else if (streq(cmd, "CONSUMER")) {
                char* stream  = zmsg_popstr(msg);
                char* pattern = zmsg_popstr(msg);
                log_debug("CONSUMER received (%s, %s)", stream, pattern);
                int r = mlm_client_set_consumer(_client, stream, pattern);
                if (r != 0) {
                    log_error("%s: can't set consumer on stream '%s', '%s'", name, stream, pattern);
                }
                zstr_free(&pattern);
                zstr_free(&stream);
            }
            else if (streq(cmd, "ALERT_ENGINE_NAME")) {
                char* alert_engine_name = zmsg_popstr(msg);
                log_debug("ALERT_ENGINE_NAME received (%s)", alert_engine_name);
                if (alert_engine_name) {
                    Autoconfig::AlertEngineName = std::string(alert_engine_name);
                }
                else {
                    log_error("%s: %s frame is missing", name, cmd);
                }
                zstr_free(&alert_engine_name);
            }
            else {
                log_debug("%s: command not handled (%s)", name, cmd);
            }

            zstr_free(&cmd);
            zmsg_destroy(&msg);

            if (term) {
                break;
            }
        }
        // Rx on client socket
        else if (which == mlm_client_msgpipe(_client)) {
            zmsg_t* msg = mlm_client_recv(_client);
            const char* command = mlm_client_command(_client);
            const char* sender = mlm_client_sender(_client);
            const char* subject = mlm_client_subject(_client);

            if (streq(command, "STREAM DELIVER")) {
                fty_proto_t* proto = fty_proto_is(msg) ? fty_proto_decode(&msg) : NULL;
                if (!proto) {
                    log_error("Can't decode message (subject='%s', sender='%s')", subject, sender);
                }
                else if (fty_proto_id(proto) == FTY_PROTO_ASSET) {
                    onSend(proto);
                }
                else {
                    log_warning("Recv unexpected stream msg (id=%d, subject='%s', sender='%s')", fty_proto_id(proto), subject, sender);
                }
                fty_proto_destroy(&proto);
            }
            else if (streq(command, "MAILBOX DELIVER")) {
                char* cmd = zmsg_popstr(msg);
                if (streq(cmd, "LIST")) {
                    char* correl_id = zmsg_popstr(msg);
                    char* filter = zmsg_popstr(msg);
                    listTemplates(correl_id, filter);
                    zstr_free(&filter);
                    zstr_free(&correl_id);
                }
                else if (streq(cmd, "OK") || streq(cmd, "ERROR")) {
                    //nop
                    //residual sendto responses alert/ADD or alert/DELETE_ELEMENT
                    //RuleConfigurator::sendNewRule'), Autoconfig::onSend()
                }
                else {
                    log_warning("Recv unexpected mailbox msg (cmd='%s', subject='%s', sender='%s')", cmd, subject, sender);
                    if (zmsg_size(msg) != 0) { zmsg_print(msg); }
                }
                zstr_free(&cmd);
            }
            else {
                log_debug("%s: Command not handled (%s)", name, command);
            }

            zmsg_destroy(&msg);
        }
    }

    log_info("%s ended", name);

    zpoller_destroy(&poller);
    mlm_client_destroy(&_client);
}

std::string Autoconfig::getEname(const std::string& assetName) const
{
    const auto it = _containers.find(assetName); // iname | ename
    return (it != _containers.end()) ? it->second : "";
}

void Autoconfig::onSend(fty_proto_t* message)
{
    if (!(message && (fty_proto_id(message) == FTY_PROTO_ASSET))) {
        return; // proto ASSET only
    }

    if (streq(fty_proto_operation(message), FTY_PROTO_ASSET_OP_INVENTORY)) {
        return; // ignore INVENTORY messages
    }

    // log_debug("== OnSend"); fty_proto_print(message);

    const std::string asset_name{fty_proto_name(message)};

    auto currentInfo = configurableDevicesGet(asset_name);

    // filter UPDATE message to ignore it when no change is detected.
    // This code is mainly to prevent overload activity on hourly REPUBLISH $all
    if (streq(fty_proto_operation(message), FTY_PROTO_ASSET_OP_UPDATE)
        && !currentInfo.empty()
        && (currentInfo == message)
    ) {
        log_debug("Asset %s UPDATED but no change detected", asset_name.c_str());
        return;
    }

    AutoConfigurationInfo info;
    info.type = fty_proto_aux_string(message, FTY_PROTO_ASSET_TYPE, "");
    info.subtype = fty_proto_aux_string(message, FTY_PROTO_ASSET_SUBTYPE, "");
    info.update_ts = fty_proto_ext_string(message, "update_ts", "");
    info.operation = fty_proto_operation(message);

    if (info.type.empty()) {
        log_debug("Extracting empty type from asset message (%s)", asset_name.c_str());
        return;
    }

    log_debug("Decoded asset='%s', type='%s', subtype='%s', operation='%s'",
        asset_name.c_str(), info.type.c_str(), info.subtype.c_str(), info.operation.c_str());

    bool updateAsset = // vs. removeAsset
        (info.operation != FTY_PROTO_ASSET_OP_DELETE)
        && streq(fty_proto_aux_string(message, FTY_PROTO_ASSET_STATUS, "active"), "active");

    // update containers map
    if (persist::is_container(info.type)) {
        if (updateAsset) {
            _containers[asset_name] = fty_proto_ext_string(message, "name", "");
        }
        else { // remove
            if (_containers.count(asset_name) != 0) {
                _containers.erase(asset_name);
            }
        }
    }

    // update configurableDevices map
    if (updateAsset)
    {
        if (!currentInfo.empty() && (info.update_ts != currentInfo.update_ts)) {
            log_debug("Changed asset %s", asset_name.c_str());
            info.configured = false;
        }

        // get ext. attributes
        info.attributes = utils::zhash_to_map(fty_proto_ext(message));

        // asset locations: inspect aux attributes 'parent_name.X' (X in [1..4]])
        info.locations.clear();
        for (int i = 1; i <= 4; i++) {
            const std::string auxName{"parent_name." + std::to_string(i)};
            const char* parentiName = fty_proto_aux_string(message, auxName.c_str(), NULL);
            if (parentiName) {
                info.locations.push_back(parentiName);
            }
        }

        configurableDevicesAdd(asset_name, info);
    }
    else // remove
    {
        configurableDevicesRemove(asset_name);

        if (info.subtype == "sensorgpio" || info.subtype == "gpo") {
            // don't do anything
        }
        else {
            const char* dest = Autoconfig::AlertEngineName.c_str();
            const char* subject = RULES_SUBJECT;
            const char* cmd = "DELETE_ELEMENT";

            log_debug("Send %s/%s %s to %s", subject, cmd, asset_name.c_str(), dest);

            // delete all rules for this asset
            zmsg_t* msg = zmsg_new();
            if (!msg) {
                log_error("zmsg_new() failed");
            }
            else {
                zmsg_addstr(msg, cmd);
                zmsg_addstr(msg, asset_name.c_str());
                int r = mlm_client_sendto(_client, dest, subject, NULL, 5000, &msg);
                // ignore response (no wait)
                if (r != 0) {
                    log_error("mlm_client_sendto() failed (dest='%s', subject='%s', cmd='%s', asset='%s')",
                        dest, subject, cmd, asset_name.c_str());
                }
            }
            zmsg_destroy(&msg);
        }
    }

    log_debug("cache size: Assets(%zu), Containers(%zu)", _configurableDevices.size(), _containers.size());

    saveState();
    setPollingInterval();
}

void Autoconfig::onPoll()
{
    bool save = false;

    {
        ConfigurableDevices_GUARD;
        TemplateRuleConfigurator trc;

        //std::map<std::string, AutoConfigurationInfo>
        for (auto& it : _configurableDevices) {
            if (zsys_interrupted) {
                return;
            }
            if (it.second.configured) {
                continue;
            }

            bool device_configured = true;
            if (trc.isApplicable(it.second))
            {
                std::string ename_la; //empty
                const auto iname_la = it.second.getAttr("logical_asset");
                if (!iname_la.empty()) { ename_la = Autoconfig::getEname(iname_la); }

                device_configured &= trc.configure(it.first, it.second, ename_la, _client);
            }
            else {
                log_info ("No applicable configurator for device '%s', not configuring", it.first.c_str ());
            }

            if (device_configured) {
                log_debug ("Device '%s' configured successfully", it.first.c_str ());
                it.second.configured = true;
                save = true;
            }
            else {
                log_debug ("Device '%s' NOT configured yet.", it.first.c_str ());
            }

            it.second.date = static_cast<uint64_t>(zclock_mono ());
        }
    }

    if (save) {
        saveState();
    }

    setPollingInterval();
}

void Autoconfig::setPollingInterval()
{
    ConfigurableDevices_GUARD;

    bool soon{false}, lazy{false};

    for (const auto& it : _configurableDevices) {
        if (zsys_interrupted) { break; }

        if (it.second.configured) {
            continue; // ignore configured devices
        }

        if (it.second.date == 0) {
            // a device that we didn't try to configure?
            soon = true; // do it soon
            break;
        }
        else {
            // a device failed to configure?
            lazy = true; // do it with laziness
        }
    }

    // timeout in ms (-1 as infinite)
    _timeout = soon ? 5000 : (lazy ? 60000 : -1);
}

void Autoconfig::loadState()
{
    ConfigurableDevices_GUARD;

    if (!std::filesystem::exists(Autoconfig::StateFile)) { return; }

    try {
        log_debug("loadState %s", Autoconfig::StateFile.c_str());

        cxxtools::SerializationInfo si;
        JSON::readFromFile(Autoconfig::StateFile, si);
        si >>= _configurableDevices;

        log_debug("loadState: %zu devices", _configurableDevices.size());
    }
    catch (const std::exception &e) {
        log_error("loadState() failed (%s, e: %s)", Autoconfig::StateFile.c_str(), e.what());
        if (errno != 0) { log_error("error: %s", strerror(errno)); }
    }
}

void Autoconfig::saveState()
{
    ConfigurableDevices_GUARD;

    if (Autoconfig::StateFile.empty()) { return; }

    try {
        log_debug("saveState %s (devices: %zu)", Autoconfig::StateFile.c_str(), _configurableDevices.size());

        cxxtools::SerializationInfo si;
        si <<= _configurableDevices;
        JSON::writeToFile(Autoconfig::StateFile, si, false);
    }
    catch (const std::exception &e) {
        log_error("saveState() failed (%s, e: %s)", Autoconfig::StateFile.c_str(), e.what());
        if (errno != 0) { log_error("error: %s", strerror(errno)); }
    }
}

std::list<std::string> Autoconfig::getAssetsThatMatchTemplate(const std::string& template_name)
{
    ConfigurableDevices_GUARD;

    TemplateRuleConfigurator trc;
    std::list<std::string> assets;

    for (const auto& it : _configurableDevices) {
        const AutoConfigurationInfo& info = it.second;
        if (trc.isApplicable(info, template_name)) {
            assets.push_back(it.first); // iname
        }
    }

    return assets;
}

void Autoconfig::listTemplates(const char* correlation_id, const char* filter)
{
    if (!correlation_id) { correlation_id = ""; }
    if (!filter) { filter = "all"; }

    log_debug("LIST templates (filter='%s', correlation_id='%s')", filter, correlation_id);

    zmsg_t* reply = zmsg_new();
    zmsg_addstr(reply, correlation_id);
    zmsg_addstr(reply, "LIST");
    zmsg_addstr(reply, filter);

    TemplateRuleConfigurator trc;
    std::vector<std::pair<std::string, std::string>> templates = trc.loadAllTemplates();

    log_debug("templates rules count: '%zu'", templates.size());

    size_t count = 0;
    for (const auto& templat : templates) {
        // ZZZ assume filter (CAT_XXX) is *only* referenced in "rule_cat" array in rule
        if (!streq(filter, "all") && (templat.second.find(filter) == std::string::npos)) {
            log_trace("template '%s' does not match", templat.first.c_str());
            continue;
        }

        // get list of elements which can apply this template
        std::string asset_list; // comma separator list
        {
            std::list<std::string> assets = getAssetsThatMatchTemplate(templat.first);
            asset_list.reserve(assets.size() * 24);

            auto templatAtPos = templat.first.find("@");
            for (const auto& asset : assets) {
                // PQSWMBT-4921 Xphase rule exceptions
                if (templatAtPos != std::string::npos) {
                    std::string ruleName{templat.first.substr(0, templatAtPos + 1) + asset};
                    if (!ruleXphaseIsApplicable(ruleName, configurableDevicesGet(asset))) {
                        continue; // skip asset
                    }
                }
                // end PQSWMBT-4921

                asset_list += (asset_list.empty() ? "" : ",") + asset;
            }
        }

        zmsg_addstr(reply, templat.first.c_str()); // rule name
        zmsg_addstr(reply, templat.second.c_str()); // json payload
        zmsg_addstr(reply, asset_list.c_str()); // assets that match the rule

        log_debug("template '%s' match for assets: '%s'", templat.first.c_str(), asset_list.c_str());
        count++;
    }

    log_debug("%zu templates match '%s'", count, filter);

    // send reply
    const char* sender = mlm_client_sender(_client);
    const char* subject = RULES_SUBJECT;
    int r = mlm_client_sendto(_client, sender, subject, mlm_client_tracker(_client), 1000, &reply);
    zmsg_destroy(&reply);
    if (r != 0) {
        log_error("mlm_client_sendto() failed (sender: %s, subject: %s, LIST)", sender, subject);
    }
}

// _configurableDevices processors

AutoConfigurationInfo Autoconfig::configurableDevicesGet(const std::string& assetName)
{
    ConfigurableDevices_GUARD;
    const auto& it = _configurableDevices.find(assetName);
    return (it != _configurableDevices.end()) ? it->second : AutoConfigurationInfo() /*empty*/;
}

void Autoconfig::configurableDevicesAdd(const std::string& assetName, const AutoConfigurationInfo& info)
{
    ConfigurableDevices_GUARD;
    log_debug("configurableDevicesAdd %s", assetName.c_str());
    _configurableDevices[assetName] = info;
}

void Autoconfig::configurableDevicesRemove(const std::string& assetName)
{
    ConfigurableDevices_GUARD;
    log_debug("configurableDevicesRemove %s", assetName.c_str());
    if (_configurableDevices.count(assetName) != 0) {
        _configurableDevices.erase(assetName);
    }
}

void Autoconfig::run(zsock_t* pipe, const std::string& name)
{
    // starting
    loadState();
    setPollingInterval();

    // main loop
    main(pipe, name);

    // ending
    saveState();
}

// external Autoconfig agent object ref.
static Autoconfig* gAgentPtr(nullptr);
static std::mutex gAgentPtrMutex;

void autoconfig(zsock_t *pipe, void *args)
{
    if (!args)
        { log_error("args is NULL"); return; }

    const std::string name{static_cast<char*>(args)};
    log_info("%s starting", name.c_str());

    Autoconfig agent;
    { std::lock_guard<std::mutex> lock(gAgentPtrMutex); gAgentPtr = &agent; }

    agent.run(pipe, name);

    { std::lock_guard<std::mutex> lock(gAgentPtrMutex); gAgentPtr = nullptr; }
}

// external accessor to _configurableDevices member of agent
AutoConfigurationInfo getAssetInfoFromAutoconfig(const std::string& assetName)
{
    std::lock_guard<std::mutex> lock(gAgentPtrMutex);
    return gAgentPtr ? gAgentPtr->configurableDevicesGet(assetName) : AutoConfigurationInfo() /*empty*/;
}

