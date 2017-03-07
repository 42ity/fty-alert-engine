/*
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
*/

/*! \file fty_alert_engine.cc
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief Starts the alert agent
 */

#include "fty_alert_engine.h"

// path to the directory, where rules are stored. Attention: without last slash!
static const char *PATH = "/var/lib/fty/alert_agent";

// agents name
static const char *AGENT_NAME = "fty-alert-engine";

// autoconfig name
static const char *AUTOCONFIG_NAME = "fty-autoconfig";

// malamute endpoint
static const char *ENDPOINT = "ipc://@/malamute";


int main (int argc, char** argv)
{
    bool set_verbose = false;
    char* fty_log_level = getenv ("BIOS_LOG_LEVEL");
    if (argc == 2 && streq (argv[1], "-v")) {
        set_verbose = true;
    }
    else if (fty_log_level && streq (fty_log_level, "LOG_DEBUG")) {
        set_verbose = true;
    }

    zactor_t *ag_server = zactor_new (fty_alert_engine_server, (void*) AGENT_NAME);
    if (set_verbose)
        zstr_sendx (ag_server, "VERBOSE", NULL);
    zstr_sendx (ag_server, "CONNECT", ENDPOINT, NULL);
    zstr_sendx (ag_server, "CONFIG", PATH, NULL);
    zstr_sendx (ag_server, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);
    zstr_sendx (ag_server, "CONSUMER", FTY_PROTO_STREAM_METRICS, ".*", NULL);
    zstr_sendx (ag_server, "CONSUMER", FTY_PROTO_STREAM_METRICS_UNAVAILABLE, ".*", NULL);

    zactor_t *ag_configurator = zactor_new (autoconfig, (void*) AUTOCONFIG_NAME);

    if (set_verbose)
        zstr_sendx (ag_configurator, "VERBOSE", NULL);
    zstr_sendx (ag_configurator, "CONNECT", ENDPOINT, NULL);
    zstr_sendx (ag_configurator, "TEMPLATES_DIR", "/usr/share/bios/fty-autoconfig", NULL);
    zstr_sendx (ag_configurator, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
    zstr_sendx (ag_configurator, "ALERT_ENGINE_NAME", AGENT_NAME, NULL);
    //  Accept and print any message back from server
    //  copy from src/malamute.c under MPL license
    while (true) {
        char *message = zstr_recv (ag_server);
        if (message) {
            puts (message);
            free (message);
        }
        else {
            puts ("interrupted");
            break;
        }
    }

    // TODO save info to persistence before I die
    zactor_destroy (&ag_server);
    return 0;
}
