/*  =========================================================================
    autoconfig - Autoconfig

    Copyright (C) 2014 - 2017 Eaton

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
    autoconfig - Autoconfig
@discuss
@end
*/

#include "fty_alert_engine_classes.h"

#include <fstream>
#include <iostream>
#include <string>

#include <cxxtools/jsonserializer.h>
#include <cxxtools/jsondeserializer.h>

#include "preproc.h"
#include "filesystem.h"
#include "utils.h"

#include "autoconfig.h"

extern int agent_alert_verbose;

#define zsys_debug1(...) \
    do { if (agent_alert_verbose) zsys_debug (__VA_ARGS__); } while (0);

#define AUTOCONFIG "AUTOCONFIG"

const std::string Autoconfig::StateFilePath = "/var/lib/fty/fty-alert-engine";
std::string Autoconfig::RuleFilePath;
const std::string Autoconfig::StateFile = "/var/lib/fty/fty-alert-engine/state";
std::string Autoconfig::AlertEngineName;

static int
load_agent_info(std::string &info)
{
    if ( !shared::is_file (Autoconfig::StateFile.c_str ())) {
        zsys_error ("not a file");
        info = "";
        return -1;
    }
    std::ifstream f(Autoconfig::StateFile, std::ios::in | std::ios::binary);
    if (f) {
        f.seekg (0, std::ios::end);
        info.resize (f.tellg ());
        f.seekg (0, std::ios::beg);
        f.read (&info[0], info.size());
        f.close ();
        return 0;
    }
    zsys_error("Fail to read '%s'", Autoconfig::StateFile.c_str ());
    return -1;
}

static int
save_agent_info(const std::string& json)
{
    if (!shared::is_dir (Autoconfig::StateFilePath.c_str ())) {
        zsys_error ("Can't serialize state, '%s' is not directory", Autoconfig::StateFilePath.c_str ());
        return -1;
    }
    try {
        std::ofstream f(Autoconfig::StateFile);
        f.exceptions (~std::ofstream::goodbit);
        f << json;
        f.close();
    }
    catch (const std::exception& e) {
        zsys_error ("Can't serialize state, %s", e.what());
        return -1;
    }
    return 0;
}

inline void operator<<= (cxxtools::SerializationInfo& si, const AutoConfigurationInfo& info)
{
    si.setTypeName("AutoConfigurationInfo");
    si.addMember("type") <<= info.type;
    si.addMember("subtype") <<= info.subtype;
    si.addMember("operation") <<= info.operation;
    si.addMember("configured") <<= info.configured;
    si.addMember("date") <<= std::to_string (info.date);
    si.addMember("attributes") <<= info.attributes;
}

inline void operator>>= (const cxxtools::SerializationInfo& si, AutoConfigurationInfo& info)
{
    std::string temp;
    si.getMember("configured") >>= info.configured;
    si.getMember("type") >>= temp;
    si.getMember("subtype") >>= temp;
    si.getMember("operation") >>= temp;
    si.getMember("date") >>= temp;
    info.date = std::stoi (temp);
    si.getMember("attributes")  >>= info.attributes;
}


void Autoconfig::main (zsock_t *pipe, char *name)
{
    if( _client ) mlm_client_destroy( &_client );
    _client = mlm_client_new ();
    assert (_client);

    zpoller_t *poller = zpoller_new (pipe, msgpipe (), NULL);
    assert (poller);
    _timestamp = zclock_mono ();
    zsock_signal (pipe, 0);

    while (!zsys_interrupted) {
        void *which = zpoller_wait (poller, _timeout);
        if (which == NULL) {
            if (zpoller_terminated (poller) || zsys_interrupted) {
                zsys_warning ("zpoller_terminated () or zsys_interrupted ()");
                break;
            }
            if (zpoller_expired (poller)) {
                onPoll ();
                _timestamp = zclock_mono ();
                continue;
            }
            _timestamp = zclock_mono ();
            zsys_warning ("zpoller_wait () returned NULL while at the same time zpoller_terminated == 0, zsys_interrupted == 0, zpoller_expired == 0");
            continue;
        }

        int64_t now = zclock_mono ();
        if (now - _timestamp >= _timeout) {
            onPoll ();
            _timestamp = zclock_mono ();
        }

        if (which == pipe) {
            zmsg_t *msg = zmsg_recv (pipe);
            char *cmd = zmsg_popstr (msg);

            if (streq (cmd, "$TERM")) {
                zsys_debug1 ("%s: $TERM received", name);
                zstr_free (&cmd);
                zmsg_destroy (&msg);
                break;
            }
            else
                if (streq (cmd, "VERBOSE")) {
                    zsys_debug1 ("%s: VERBOSE received", name);
                    agent_alert_verbose = true;
                }
                else
                    if (streq (cmd, "TEMPLATES_DIR")) {
                        zsys_debug1 ("TEMPLATES_DIR received");
                        char* dirname = zmsg_popstr (msg);
                        if (dirname) {
                            Autoconfig::RuleFilePath = std::string (dirname);
                        }
                        else {
                            zsys_error ("%s: in TEMPLATES_DIR command next frame is missing", name);
                        }
                        zstr_free (&dirname);
                    }
                    else
                        if (streq (cmd, "CONNECT")) {
                            zsys_debug1 ("CONNECT received");
                            char* endpoint = zmsg_popstr (msg);
                            int rv = mlm_client_connect (_client, endpoint, 1000, name);
                            if (rv == -1)
                                zsys_error ("%s: can't connect to malamute endpoint '%s'", name, endpoint);
                            zstr_free (&endpoint);
                        }
                        else
                            if (streq (cmd, "CONSUMER")) {
                                zsys_debug1 ("CONSUMER received");
                                char* stream = zmsg_popstr (msg);
                                char* pattern = zmsg_popstr (msg);
                                int rv = mlm_client_set_consumer (_client, stream, pattern);
                                if (rv == -1)
                                    zsys_error ("%s: can't set consumer on stream '%s', '%s'", name, stream, pattern);
                                zstr_free (&pattern);
                                zstr_free (&stream);
                            }
                            else
                                if (streq (cmd, "ALERT_ENGINE_NAME")) {
                                    zsys_debug1 ("ALERT_ENGINE_NAME received");
                                char* alert_engine_name = zmsg_popstr (msg);
                                if (alert_engine_name) {
                                    Autoconfig::AlertEngineName = std::string (alert_engine_name);
                                }
                                else {
                                    zsys_error ("%s: in ALERT_ENGINE_NAME command next frame is missing", name);
                                }
                                zstr_free (&alert_engine_name);
                                }

            zstr_free (&cmd);
            zmsg_destroy (&msg);
            continue;
        }

        zmsg_t *message = recv ();
        if (!message) {
            zsys_warning ("recv () returned NULL; zsys_interrupted == '%s'; command = '%s', subject = '%s', sender = '%s'",
                    zsys_interrupted ? "true" : "false", command (), subject (), sender ());
            continue;
        }
        if (is_fty_proto (message)) {
            fty_proto_t *bmessage = fty_proto_decode (&message);
            if (!bmessage ) {
                zsys_error ("can't decode message with subject %s, ignoring", subject ());
                continue;
            }

            if (fty_proto_id (bmessage) == FTY_PROTO_ASSET) {
                onSend (&bmessage);
                fty_proto_destroy (&bmessage);
                continue;
            }
            else {
                zsys_warning ("Weird fty_proto msg received, id = '%d', command = '%s', subject = '%s', sender = '%s'",
                        fty_proto_id (bmessage), command (), subject (), sender ());
                fty_proto_destroy (&bmessage);
                continue;
            }
        }
        else {
            // this should be a message from ALERT_ENGINE_NAME (fty-alert-engine or fty-alert-flexible)
            if (streq (sender (), "fty-alert-engine") ||
                streq (sender (), "fty-alert-flexible")) {
                char *reply = zmsg_popstr (message);
                if (streq (reply, "OK")) {
                    char *details = zmsg_popstr (message);
                    zsys_debug ("Received OK for rule '%s'", details);
                    zstr_free (&details);
                }
                else {
                    if (streq (reply, "ERROR")) {
                        char *details = zmsg_popstr (message);
                        zsys_error ("Received ERROR : '%s'", details);
                        zstr_free (&details);
                    }
                    else
                        zsys_warning ("Unexpected message received, command = '%s', subject = '%s', sender = '%s'",
                            command (), subject (), sender ());
                }
                zstr_free (&reply);
            }
            else
                zsys_warning ("Message from unknown sender received: sender = '%s', command = '%s', subject = '%s'.",
                              sender (), command (), subject ());
            zmsg_destroy (&message);
        }
    }
    zpoller_destroy (&poller);
}


void
Autoconfig::onSend (fty_proto_t **message)
{
    if (!message || ! *message)
        return;

    AutoConfigurationInfo info;
    std::string device_name (fty_proto_name (*message));
    info.type.assign (fty_proto_aux_string (*message, "type", ""));
    info.subtype.assign (fty_proto_aux_string (*message, "subtype", ""));
    info.operation.assign (fty_proto_operation (*message));

    if (info.type.empty ()) {
        zsys_debug("extracting attibutes from asset message failed.");
        return;
    }
    zsys_debug("Decoded asset message - device name = '%s', type = '%s', subtype = '%s', operation = '%s'",
            device_name.c_str (), info.type.c_str (), info.subtype.c_str (), info.operation.c_str ());
    info.attributes = utils::zhash_to_map(fty_proto_ext (*message));
    _configurableDevices.emplace (std::make_pair (device_name, info));
    saveState ();
    setPollingInterval();
}

void Autoconfig::onPoll( )
{
    static TemplateRuleConfigurator iTemplateRuleConfigurator;

    bool save = false;

    for (auto& it : _configurableDevices) {
        if (it.second.configured) {
            continue;
        }

        bool device_configured = true;
        if (zsys_interrupted)
            return;

        if ((&iTemplateRuleConfigurator)->isApplicable (it.second))
            device_configured &= (&iTemplateRuleConfigurator)->configure (it.first, it.second, client ());
        else
            zsys_info ("No applicable configurator for device '%s', not configuring", it.first.c_str ());

        if (device_configured) {
            zsys_debug ("Device '%s' configured successfully", it.first.c_str ());
            it.second.configured = true;
            save = true;
        }
        else {
            zsys_debug ("Device '%s' NOT configured yet.", it.first.c_str ());
        }
        it.second.date = zclock_mono ();
    }

    if (save) {
        cleanupState();
        saveState();
    }
    setPollingInterval();
}

// autoconfig agent private methods

void Autoconfig::setPollingInterval( )
{
    _timeout = -1;
    for( auto &it : _configurableDevices) {
        if( ! it.second.configured ) {
            if( it.second.date == 0 ) {
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
    std::string json = "";
    int rv = load_agent_info(json);
    if ( rv != 0 || json.empty() )
        return;

    try {
        std::istringstream in(json);
        _configurableDevices.clear();
        cxxtools::JsonDeserializer deserializer(in);
        deserializer.deserialize(_configurableDevices);
    } catch(const std::exception &e ) {
        zsys_error( "can't parse state: %s", e.what() );
    }
}


void Autoconfig::cleanupState()
{
    zsys_debug ("Size before cleanup '%zu'", _configurableDevices.size ());
    for( auto it = _configurableDevices.cbegin(); it != _configurableDevices.cend() ; ) {
        if( it->second.configured ) {
            _configurableDevices.erase(it++);
        } else {
            ++it;
        }
    }
    zsys_debug ("Size after cleanup '%zu'", _configurableDevices.size ());
}

void Autoconfig::saveState()
{
    std::ostringstream stream;
    cxxtools::JsonSerializer serializer(stream);
    zsys_debug ("size = '%zu'",_configurableDevices.size ());
    serializer.serialize( _configurableDevices );
    serializer.finish();
    std::string json = stream.str();
    zsys_debug (json.c_str ());
    save_agent_info(json );
}

void autoconfig (zsock_t *pipe, void *args )
{
    char *name = (char *)args;
    zsys_info ("autoconfig agent started");
    Autoconfig agent( AUTOCONFIG );
    agent.run(pipe, name);
    zsys_info ("autoconfig agent exited");
}

void
autoconfig_test (bool verbose)
{
    printf (" * autoconfig: ");
    printf ("OK\n");
}
