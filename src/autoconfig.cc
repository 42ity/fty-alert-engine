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

// malamute endpoint
static const char *ENDPOINT = "ipc://@/malamute";

const char* Autoconfig::StateFilePath = "/var/lib/bios/agent-autoconfig";
const char* Autoconfig::RuleFilePath = "/usr/share/bios/fty-autoconfig";
const char* Autoconfig::StateFile = "/var/lib/bios/agent-autoconfig/state";

static int
load_agent_info(std::string &info)
{
    if ( !shared::is_file (Autoconfig::StateFile)) {
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
    zsys_error("Fail to read '%s'", Autoconfig::StateFile);
    return -1; 
}

static int
save_agent_info(const std::string& json)
{   
    if (!shared::is_dir (Autoconfig::StateFilePath)) {
        zsys_error ("Can't serialize state, '%s' is not directory", Autoconfig::StateFilePath);
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
    zsock_t *client_pipe = msgpipe();
    if (!client_pipe) {
        zsys_error ("msgpipe () failed");
        return;
    }

    zpoller_t *poller = zpoller_new (pipe, client_pipe, NULL);
    if (!poller) {
        zsys_error ("zpoller_new () failed");
        return;
    }

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
                            Autoconfig::RuleFilePath = strdup (dirname);
                        }
                        else {
                            zsys_error ("%s: in TEMPLATES_DIR command next frame is missing", name);
                        }
                        zstr_free (&dirname);
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
                zmsg_destroy (&message);
                continue;
            }

            if (fty_proto_id (bmessage) == FTY_PROTO_ASSET) {
                onSend (&bmessage);
                continue;
            }
            else {    
                zsys_warning ("Weird zmsg received, id = '%d', command = '%s', subject = '%s', sender = '%s'",
                        fty_proto_id (bmessage), command (), subject (), sender ());
                continue;
            }
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
    const char *device_name = fty_proto_name (*message);
    info.type = fty_proto_aux_string (*message, "type", NULL);
    info.subtype = fty_proto_aux_string (*message, "subtype", NULL);
    info.operation = fty_proto_operation (*message);

    if (info.type == NULL) {
        zsys_debug("extracting attibutes from asset message failed.");
        return;
    }   
    zsys_debug("Decoded asset message - device name = '%s', type = '%s', subtype = '%s', operation = '%s'",
            device_name, info.type, info.subtype, info.operation);
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
        else { 
            zsys_info ("No applicable configurator for device '%s', not configuring", it.first.c_str ());
            continue;
        }
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
    if( agent.connect( ENDPOINT, FTY_PROTO_STREAM_ASSETS, ".*" ) ) {
        agent.run(pipe, name);
    } else {
        zsys_error ("autoconfig agent could not connect to message bus");
    }
    zsys_info ("autoconfig agent exited");
}   

