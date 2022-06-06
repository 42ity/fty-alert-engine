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
#include <cxxtools/jsondeserializer.h>
#include <cxxtools/jsonserializer.h>
#include <fstream>
#include <fty_common_filesystem.h>
#include <fty_log.h>
#include <iostream>
#include <lua.h>

#define AUTOCONFIG "AUTOCONFIG"

std::string Autoconfig::StateFilePath;
std::string Autoconfig::RuleFilePath;
std::string Autoconfig::StateFile;
std::string Autoconfig::AlertEngineName;

static int load_agent_info(std::string& json)
{
    json.clear();
    log_debug("load_agent_info '%s'", Autoconfig::StateFile.c_str());

    if (!shared::is_file(Autoconfig::StateFile.c_str())) {
        log_error("'%s' is not a file", Autoconfig::StateFile.c_str());
        return -1;
    }

    std::ifstream f(Autoconfig::StateFile, std::ios::in | std::ios::binary);
    if (f) {
        f.seekg(0, std::ios::end);
        json.resize(static_cast<size_t>(f.tellg()));
        f.seekg(0, std::ios::beg);
        f.read(&json[0], static_cast<std::streamsize>(json.size()));
        f.close();
        return 0;
    }
    log_error("Fail to read '%s'", Autoconfig::StateFile.c_str());
    return -1;
}

static int save_agent_info(const std::string& json)
{
    log_info("save in '%s'", Autoconfig::StateFile.c_str());

    if (!shared::is_dir(Autoconfig::StateFilePath.c_str())) {
        log_error("Can't serialize state, '%s' is not directory", Autoconfig::StateFilePath.c_str());
        return -1;
    }
    try {
        std::ofstream f(Autoconfig::StateFile);
        f.exceptions(~std::ofstream::goodbit);
        f << json;
        f.close();
    } catch (const std::exception& e) {
        log_error("Can't serialize state, %s", e.what());
        return -1;
    }
    return 0;
}

inline void operator<<=(cxxtools::SerializationInfo& si, const AutoConfigurationInfo& info)
{
    si.setTypeName("AutoConfigurationInfo");
    si.addMember("type") <<= info.type;
    si.addMember("subtype") <<= info.subtype;
    si.addMember("operation") <<= info.operation;
    si.addMember("configured") <<= info.configured;
    si.addMember("date") <<= std::to_string(info.date);
    si.addMember("attributes") <<= info.attributes;
    si.addMember("locations") <<= info.locations;
}

inline void operator>>=(const cxxtools::SerializationInfo& si, AutoConfigurationInfo& info)
{
    std::string temp;
    si.getMember("configured") >>= info.configured;
    si.getMember("type") >>= temp;
    si.getMember("subtype") >>= temp;
    si.getMember("operation") >>= temp;
    si.getMember("date") >>= temp;
    info.date = static_cast<uint64_t>(std::stoi(temp));
    si.getMember("attributes") >>= info.attributes;
    si.getMember("locations") >>= info.locations;
}

// multi-thread access guard for _configurableDevices map
#define ConfigurableDevices_GUARD \
    std::lock_guard<std::recursive_mutex> guard(_configurableDevicesMutex)

void Autoconfig::main (zsock_t* pipe, char* name)
{
    if (_client)
        mlm_client_destroy(&_client);
    _client = mlm_client_new();
    assert(_client);

    zpoller_t* poller = zpoller_new(pipe, msgpipe(), NULL);
    assert(poller);

    log_info("%s started", name);
    zsock_signal(pipe, 0);

    _timestamp = zclock_mono();

    while (!zsys_interrupted) {

        void* which = zpoller_wait(poller, _timeout);

        if (which == NULL) {
            if (zpoller_terminated(poller) || zsys_interrupted) {
                log_debug("%s: terminated", name);
                break;
            }
            if (zpoller_expired(poller)) {
                onPoll();
                _timestamp = zclock_mono();
                continue;
            }
            _timestamp = zclock_mono();
            log_warning(
                "zpoller_wait () returned NULL while at the same time zpoller_terminated == 0, zsys_interrupted == 0, "
                "zpoller_expired == 0");
            continue;
        }

        int64_t now = zclock_mono();
        if ((now - _timestamp) >= _timeout) {
            onPoll();
            _timestamp = zclock_mono();
        }

        if (which == pipe) {
            zmsg_t* msg = zmsg_recv(pipe);
            char*   cmd = zmsg_popstr(msg);

            if (streq(cmd, "$TERM")) {
                log_debug("%s: $TERM received", name);
                zstr_free(&cmd);
                zmsg_destroy(&msg);
                break;
            }

            if (streq(cmd, "TEMPLATES_DIR")) {
                char* dirname = zmsg_popstr(msg);
                log_debug("TEMPLATES_DIR received (%s)", dirname);
                if (dirname) {
                    Autoconfig::RuleFilePath = std::string(dirname);
                } else {
                    log_error("%s: in TEMPLATES_DIR command next frame is missing", name);
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
                } else {
                    log_error("%s: in CONFIG command next frame is missing", name);
                }
                zstr_free(&dirname);
            }
            else if (streq(cmd, "CONNECT")) {
                char* endpoint = zmsg_popstr(msg);
                log_debug("CONNECT received (%s)", endpoint);
                int rv = mlm_client_connect(_client, endpoint, 1000, name);
                if (rv == -1) {
                    log_error("%s: can't connect to malamute endpoint '%s'", name, endpoint);
                }
                zstr_free(&endpoint);
            }
            else if (streq(cmd, "CONSUMER")) {
                char* stream  = zmsg_popstr(msg);
                char* pattern = zmsg_popstr(msg);
                log_debug("CONSUMER received (%s, %s)", stream, pattern);
                int rv = mlm_client_set_consumer(_client, stream, pattern);
                if (rv == -1) {
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
                } else {
                    log_error("%s: in ALERT_ENGINE_NAME command next frame is missing", name);
                }
                zstr_free(&alert_engine_name);
            }
            else {
                log_debug("%s: command not handled (%s)", name, cmd);
            }

            zstr_free(&cmd);
            zmsg_destroy(&msg);
            continue;
        }

        //TODO rewrite that crappy message processing

        zmsg_t* message = recv();
        if (!message) {
            log_warning(
                "recv () returned NULL; zsys_interrupted == '%s'; command = '%s', subject = '%s', sender = '%s'",
                zsys_interrupted ? "true" : "false", command(), subject(), sender());
        }
        else if (fty_proto_is(message)) {
            fty_proto_t* bmessage = fty_proto_decode(&message);
            if (!bmessage) {
                log_error("can't decode message with subject %s, ignoring", subject());
            }
            else if (fty_proto_id(bmessage) == FTY_PROTO_ASSET) {
                if (!streq(fty_proto_operation(bmessage), FTY_PROTO_ASSET_OP_INVENTORY)) {
                    onSend(&bmessage);
                }
            } else {
                log_warning("Weird fty_proto msg received, id = '%d', command = '%s', subject = '%s', sender = '%s'",
                    fty_proto_id(bmessage), command(), subject(), sender());
            }
            fty_proto_destroy(&bmessage);
        }
        else {
            // this should be a message from ALERT_ENGINE_NAME (fty-alert-engine or fty-alert-flexible)
            if (streq(sender(), "fty-alert-engine") || streq(sender(), "fty-alert-flexible")) {
                char* reply = zmsg_popstr(message);
                if (streq(reply, "OK")) {
                    if (zmsg_size(message) == 1) {
                        char* details = zmsg_popstr(message);
                        log_debug("Received OK for rule '%s'", details);
                        zstr_free(&details);
                    } else {
                        log_debug("Received OK for %zu rules", zmsg_size(message));
                    }
                } else {
                    if (streq(reply, "ERROR")) {
                        char* details = zmsg_popstr(message);
                        log_error("Received ERROR : '%s'", details);
                        zstr_free(&details);
                    } else
                        log_warning("Unexpected message received, command = '%s', subject = '%s', sender = '%s'",
                            command(), subject(), sender());
                }
                zstr_free(&reply);
            } else {
                char* cmd = zmsg_popstr(message);
                if (streq(cmd, "LIST")) {
                    char* correl_id = zmsg_popstr(message);
                    char* filter    = zmsg_popstr(message);
                    listTemplates(correl_id, filter);
                    zstr_free(&correl_id);
                    zstr_free(&filter);
                } else {
                    log_warning("Unexpected message received, command = '%s', subject = '%s', sender = '%s'", command(),
                        subject(), sender());
                }
                zstr_free(&cmd);
            }
        }
        zmsg_destroy(&message);
    }

    log_info("%s ended", name);
    zpoller_destroy(&poller);
}

const std::string Autoconfig::getEname(const std::string& iname)
{
    std::string ename;
    auto        search = _containers.find(iname); // iname | ename
    if (search != _containers.end())
        ename = search->second;
    return ename;
}

void Autoconfig::onSend(fty_proto_t** message)
{
    if (!message || !*message)
        return;

    std::string device_name (fty_proto_name (*message));
    auto currentInfo = configurableDevicesGet(device_name);

    //filter UPDATE message to ignore it when no change is detected.
    //This code is mainly to prevent overload activity on hourly REPUBLISH $all
    if ((strcmp(fty_proto_operation (*message), FTY_PROTO_ASSET_OP_UPDATE) == 0)
        && !currentInfo.empty()
        && (currentInfo == *message))
    {
        log_debug("asset %s UPDATED but no change detected => ignore it", device_name.c_str());
        return;
    }

    AutoConfigurationInfo info;
    info.type.assign (fty_proto_aux_string (*message, "type", ""));
    info.subtype.assign (fty_proto_aux_string (*message, "subtype", ""));
    info.operation.assign (fty_proto_operation (*message));
    info.update_ts.assign (fty_proto_ext_string(*message, "update_ts", ""));

    if (!currentInfo.empty()
        && (0 != strcmp(fty_proto_ext_string(*message, "update_ts", ""), currentInfo.update_ts.c_str()))
    ){
        log_debug("Changed asset, updating");
        info.configured = false;
    }

    if (streq(fty_proto_aux_string(*message, "type", ""), "datacenter") ||
        streq(fty_proto_aux_string(*message, "type", ""), "room") ||
        streq(fty_proto_aux_string(*message, "type", ""), "row") ||
        streq(fty_proto_aux_string(*message, "type", ""), "rack")) {
        if (info.operation != FTY_PROTO_ASSET_OP_DELETE &&
            streq(fty_proto_aux_string(*message, FTY_PROTO_ASSET_STATUS, "active"), "active")) {
            _containers[device_name] = fty_proto_ext_string(*message, "name", "");
        } else {
            try {
                _containers.erase(device_name);
            }
            catch (const std::exception &e) {
                log_error( "can't erase container %s: %s", device_name.c_str(), e.what() );
            }
        }
    }

    if (info.type.empty ()) {
        log_debug("extracting attributes from asset message failed.");
        return;
    }

    if (streq(info.type.c_str(), "datacenter") ||
            streq(info.type.c_str(), "room") ||
            streq(info.type.c_str(), "row") ||
            streq(info.type.c_str(), "rack"))
    {
        _containers.emplace(device_name, fty_proto_ext_string(*message, "name", ""));
    }

    log_debug("Decoded asset message - device name = '%s', type = '%s', subtype = '%s', operation = '%s'",
        device_name.c_str(), info.type.c_str(), info.subtype.c_str(), info.operation.c_str());
    info.attributes = utils::zhash_to_map(fty_proto_ext(*message));

    // asset locations, inspect aux attributes 'parent_name.X' (X in [1..4]])
    info.locations.clear();
    for (int i = 1; i <= 4; i++) {
        const std::string auxName{"parent_name." + std::to_string(i)};
        const char* parentiName = fty_proto_aux_string(*message, auxName.c_str(), NULL);
        if (parentiName) {
            info.locations.push_back(parentiName);
        }
    }

    if (info.operation != FTY_PROTO_ASSET_OP_DELETE
        && streq (fty_proto_aux_string (*message, FTY_PROTO_ASSET_STATUS, "active"), "active"))
    {
        configurableDevicesAdd(device_name, info);
    }
    else
    {
        configurableDevicesRemove(device_name);

        if (info.subtype == "sensorgpio" || info.subtype == "gpo") {
            // don't do anything
        } else {
            const char* dest = Autoconfig::AlertEngineName.c_str();
            log_info("Sending DELETE_ELEMENT for %s to %s", device_name.c_str(), dest);

            // delete all rules for this asset
            zmsg_t* msg = zmsg_new();
            zmsg_addstr(msg, "DELETE_ELEMENT");
            zmsg_addstr(msg, device_name.c_str());
            if (sendto(dest, "rfc-evaluator-rules", &msg) != 0) {
                log_error("mlm_client_sendto (address = '%s', subject = '%s', timeout = '5000') failed.", dest,
                    "rfc-evaluator-rules");
            }
            zmsg_destroy(&msg);
        }
    }
    saveState();
    setPollingInterval();
}

void Autoconfig::onPoll()
{
    static TemplateRuleConfigurator iTemplateRuleConfigurator;

    bool save = false;

    {
        ConfigurableDevices_GUARD;
        //std::map<std::string, AutoConfigurationInfo>
        for (auto& it : _configurableDevices) {
            if (zsys_interrupted)
                return;
            if (it.second.configured)
                continue;

            bool device_configured = true;
            if (iTemplateRuleConfigurator.isApplicable (it.second))
            {
                std::string la;
                for (auto &i : it.second.attributes)
                {
                    if (i.first == "logical_asset")
                        la = i.second;
                }

                device_configured &= iTemplateRuleConfigurator.configure (
                    it.first, it.second,
                    Autoconfig::getEname (la), client ()
                );
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
        cleanupState();
        saveState();
    }
    setPollingInterval();
}

// autoconfig agent private methods

void Autoconfig::setPollingInterval()
{
    _timeout = -1;

    ConfigurableDevices_GUARD;
    for ( auto &it : _configurableDevices) {
        if ( ! it.second.configured ) {
            if ( it.second.date == 0 ) {
                // there is device that we didn't try to configure
                // let's try to do it soon
                _timeout = 5000;
                return;
            } else {
                // we failed to configure some device
                // let's try after one minute again
                _timeout = 60000;
            }
        }
    }
}

void Autoconfig::loadState()
{
    std::string json;
    int rv = load_agent_info(json);
    if (rv != 0 || json.empty())
        return;

    try {
        ConfigurableDevices_GUARD;
        std::istringstream in(json);
        _configurableDevices.clear();
        cxxtools::JsonDeserializer deserializer(in);
        deserializer.deserialize(_configurableDevices);

        log_debug("loadState: State file size: %zu", _configurableDevices.size());
    }
    catch (const std::exception &e) {
        log_error( "can't parse state: %s", e.what() );
    }
}

void Autoconfig::cleanupState()
{
    log_debug("cleanupState: State file size: %zu", _configurableDevices.size());

    // Just set the state file to empty
    save_agent_info("");
    return;
}

void Autoconfig::saveState()
{
    ConfigurableDevices_GUARD;

    log_debug("saveState: State file size: %zu", _configurableDevices.size());

    std::ostringstream stream;
    cxxtools::JsonSerializer serializer(stream);
    serializer.serialize(_configurableDevices);
    serializer.finish();
    std::string json{stream.str()};
    save_agent_info(json);
}

std::list<std::string> Autoconfig::getElemenListMatchTemplate(std::string template_name)
{
    TemplateRuleConfigurator templateRuleConfigurator;
    std::list<std::string>   elementList;

    ConfigurableDevices_GUARD;
    for (auto& it : _configurableDevices) {
        AutoConfigurationInfo info = it.second;
        if (templateRuleConfigurator.isApplicable(info, template_name)) {
            elementList.push_back(it.first);
        }
    }
    return elementList;
}

void Autoconfig::listTemplates(const char* correlation_id, const char* filter)
{
    if (!correlation_id)
        correlation_id = "";
    if (!filter)
        filter = "all";

    log_debug("DO REQUEST LIST template '%s' correl_id '%s'", filter, correlation_id);

    zmsg_t* reply = zmsg_new();
    zmsg_addstr(reply, correlation_id);
    zmsg_addstr(reply, "LIST");
    zmsg_addstr(reply, filter);

    TemplateRuleConfigurator templateRuleConfigurator;
    std::vector<std::pair<std::string, std::string>> templates = templateRuleConfigurator.loadAllTemplates();
    log_debug("templates rules count: '%zu'", templates.size());

    int count = 0;
    for (const auto& templat : templates) {
        //ZZZ assume filter (CAT_XXX) is only referenced in "rule_cat" array in rule
        if (!streq(filter, "all") && (templat.second.find(filter) == std::string::npos)) {
            log_trace("templates '%s' does not match", templat.first.c_str());
            continue;
        }

        zmsg_addstr (reply, templat.first.c_str()); //rule name
        zmsg_addstr (reply, templat.second.c_str()); //json payload

        //get list of element which can apply this template
        std::string asset_list; //comma separator list
        {
            std::list<std::string> elements = getElemenListMatchTemplate(templat.first.c_str());
            auto templatAtPos = templat.first.find("@");
            for (const auto &element : elements) {
                // PQSWMBT-4921 Xphase rule exceptions
                if (templatAtPos != std::string::npos) {
                    std::string ruleName{templat.first.substr(0, templatAtPos + 1) + element};
                    if (!ruleXphaseIsApplicable(ruleName, configurableDevicesGet(element)))
                        continue; // skip element
                }
                // end PQSWMBT-4921

                asset_list += (asset_list.empty() ? "" : ",") + element;
            }
        }

        zmsg_addstr (reply, asset_list.c_str());

        log_debug ("template: '%s', assets: '%s' match",
            templat.first.c_str(), asset_list.c_str());

        count++;
    }

    log_debug("%zu templates match '%s'", count, filter);

    mlm_client_sendto(_client, sender(), RULES_SUBJECT, mlm_client_tracker(_client), 1000, &reply);
    zmsg_destroy(&reply);
}

// _configurableDevices processors

AutoConfigurationInfo Autoconfig::configurableDevicesGet(const std::string& assetName)
{
    ConfigurableDevices_GUARD;
    auto it = _configurableDevices.find(assetName);
    if (it != _configurableDevices.end())
        return it->second;
    return AutoConfigurationInfo(); // empty
}

void Autoconfig::configurableDevicesAdd(const std::string& assetName, const AutoConfigurationInfo& info)
{
    ConfigurableDevices_GUARD;
    _configurableDevices[assetName] = info;
}

bool Autoconfig::configurableDevicesRemove(const std::string& assetName)
{
    ConfigurableDevices_GUARD;
    try {
        _configurableDevices.erase(assetName);
        return true; // success
    }
    catch (const std::exception &e) {
        log_error( "can't erase device %s: %s", assetName.c_str(), e.what() );
    }
    return false;
}

// external Autoconfig agent object ref.
static Autoconfig* gAgentPtr(nullptr);
static std::mutex gAgentPtrMutex;

void autoconfig (zsock_t *pipe, void *args )
{
    log_debug ("autoconfig agent started");

    Autoconfig agent(AUTOCONFIG);
    { std::lock_guard<std::mutex> lock(gAgentPtrMutex); gAgentPtr = &agent; }

    char *name = static_cast<char*>(args);
    agent.run(pipe, name);

    { std::lock_guard<std::mutex> lock(gAgentPtrMutex); gAgentPtr = nullptr; }

    log_info ("autoconfig agent ended");
}

// external accessor to _configurableDevices member of agent
AutoConfigurationInfo getAssetInfoFromAutoconfig(const std::string& assetName)
{
    //log_debug ("getAssetInfoFromAutoconfig");
    std::lock_guard<std::mutex> lock(gAgentPtrMutex);
    if (gAgentPtr)
        return gAgentPtr->configurableDevicesGet(assetName);
    return AutoConfigurationInfo(); //empty
}

