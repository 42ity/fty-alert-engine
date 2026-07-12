/*
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
*/

#include "fty_alert_engine_server.h"
#include "fty_alert_actions.h"
#include "autoconfig.h"
#include "misc/audit_log.h"

#include <fty_common_mlm.h>
#include <czmq.h>

// rule instances storage, CAUTION: **without** ending slash!
static const char* RULES_DIR = "/var/lib/fty/fty-alert-engine";
// rule templates storage
static const char* TEMPLATES_DIR = "/usr/share/bios/fty-autoconfig";

// agent names
static const char* ENGINE_AGENT_NAME        = "fty-alert-engine";
static const char* ENGINE_AGENT_NAME_STREAM = "fty-alert-engine-stream";
static const char* ACTIONS_AGENT_NAME       = "fty-alert-actions";
static const char* AUTOCONFIG_AGENT_NAME    = "fty-autoconfig";

// flexible rules agent
static const char* FLEXIBLE_AGENT_NAME = "fty-alert-flexible";

static const char* SETTINGS_VOLTAGE_STD_DEFAULT = "EUROPE";

int main(int argc, char** argv)
{
    // defaults
    const char* config_file = NULL;
    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        const std::string arg{argv[i]};
        const char* param = ((i + 1) < argc) ? argv[i + 1] : NULL;

        if (arg == "-v" || arg == "--verbose") {
            verbose = true;
        }
        else if (arg == "-h" || arg == "--help") {
            printf("%s [option] [value]\n", argv[0]);
            printf("   -v|--verbose          verbose output\n");
            printf("   -c|--config [path]    use custom config file\n");
            printf("   -h|--help             print this help\n");
            return EXIT_SUCCESS;
        }
        else if (arg == "-c" || arg == "--config") {
            if (!param) {
                fprintf(stderr, "ERROR: Missing parameter (option: %s)\n", arg.c_str());
                return EXIT_FAILURE;
            }
            config_file = param;
            i++;
        }
        else {
            fprintf(stderr, "ERROR: Unknown option (%s)\n", arg.c_str());
            return EXIT_FAILURE;
        }
    }

    ManageFtyLog::setInstanceFtylog(ENGINE_AGENT_NAME, FTY_COMMON_LOGGING_DEFAULT_CFG);

    char* settings_voltage_standard = strdup(SETTINGS_VOLTAGE_STD_DEFAULT); //default

    #define CLEANUP \
        do { \
            zstr_free(&settings_voltage_standard); \
        } while(0)

    if (config_file) {
        zconfig_t* config = zconfig_load(config_file);
        if (!config) {
            log_error("Failed to load %s", config_file);
        }
        else {
            log_info("Loading %s", config_file);

            // Note: server/[timeout,background,workdir] ignored
            verbose = streq(zconfig_get(config, "server/verbose", "false"), "true");

            const char* vs = zconfig_get(config, "settings/voltage_standard", SETTINGS_VOLTAGE_STD_DEFAULT);
            zstr_free(&settings_voltage_standard);
            settings_voltage_standard = strdup(vs);
        }
        zconfig_destroy(&config);
    }

    if (verbose) {
        ManageFtyLog::getInstanceFtylog()->setVerboseMode();
    }

    // initialize log for auditability
    AuditLog::init(ENGINE_AGENT_NAME);

    log_debug ("%s starting...", ENGINE_AGENT_NAME);

    // initialize actors
    zactor_t* mailbox_actor = NULL;
    zactor_t* stream_actor = NULL;
    zactor_t* autoconf_actor = NULL;
    zactor_t* action_actor = NULL;
    bool actors_initOK{false};
    do {
        zactor_t* actor = NULL;

        // alert-engine mailbox actor
        mailbox_actor = actor = zactor_new(fty_alert_engine_mailbox, static_cast<void*>(const_cast<char*>(ENGINE_AGENT_NAME)));
        if (!actor) break;
        zstr_sendx(actor, "CONFIG", RULES_DIR, NULL); // rule instances
        zstr_sendx(actor, "CONNECT", MLM_ENDPOINT, NULL);
        zstr_sendx(actor, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);

        // alert-engine stream actor
        stream_actor = actor = zactor_new(fty_alert_engine_stream, static_cast<void*>(const_cast<char*>(ENGINE_AGENT_NAME_STREAM)));
        if (!actor) break;
        zstr_sendx(actor, "CONNECT", MLM_ENDPOINT, NULL);
        zstr_sendx(actor, "PRODUCER", FTY_PROTO_STREAM_ALERTS_SYS, NULL);

        // autoconfig actor
        autoconf_actor = actor = zactor_new(autoconfig, static_cast<void*>(const_cast<char*>(AUTOCONFIG_AGENT_NAME)));
        if (!actor) break;
        zstr_sendx(actor, "CONFIG", RULES_DIR, NULL); // actor state file
        zstr_sendx(actor, "CONNECT", MLM_ENDPOINT, NULL);
        zstr_sendx(actor, "TEMPLATES_DIR", TEMPLATES_DIR, NULL); // rule templates
        zstr_sendx(actor, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
        zstr_sendx(actor, "ALERT_ENGINE_NAME", ENGINE_AGENT_NAME, NULL);
        zstr_sendx(actor, "ALERT_FLEXIBLE_NAME", FLEXIBLE_AGENT_NAME, NULL);
        zstr_sendx(actor, "SETTINGS_VOLTAGE_STANDARD", settings_voltage_standard, NULL);

        // alert actions actor
        action_actor = actor = zactor_new(fty_alert_actions, static_cast<void*>(const_cast<char*>(ACTIONS_AGENT_NAME)));
        if (!actor) break;
        zstr_sendx(actor, "CONNECT", MLM_ENDPOINT, NULL);
        zstr_sendx(actor, "CONSUMER", FTY_PROTO_STREAM_ASSETS, ".*", NULL);
        zstr_sendx(actor, "CONSUMER", FTY_PROTO_STREAM_ALERTS, ".*", NULL);
        zstr_sendx(actor, "ASSETS_REPUBLISH", NULL); // republish all assets

        actors_initOK = true;
        break;
    } while(0);

    if (!actors_initOK) {
        log_error("%s starting failed", ENGINE_AGENT_NAME);
        zactor_destroy(&action_actor);
        zactor_destroy(&autoconf_actor);
        zactor_destroy(&stream_actor);
        zactor_destroy(&mailbox_actor);
        CLEANUP;
        AuditLog::deinit(); // release audit context
        return EXIT_FAILURE;
    }

    log_info("%s started", ENGINE_AGENT_NAME);

    // main loop, accept any message back from server
    // copy from src/malamute.c under MPL license
    while (!zsys_interrupted) {
        char* msg = zstr_recv(mailbox_actor);
        if (!msg) {
            break;
        }

        log_debug("%s: recv msg '%s'", ENGINE_AGENT_NAME, msg);
        zstr_free(&msg);
    }

    log_info("%s ended", ENGINE_AGENT_NAME);

    zactor_destroy(&action_actor);
    zactor_destroy(&autoconf_actor);
    zactor_destroy(&stream_actor);
    zactor_destroy(&mailbox_actor);
    CLEANUP;
    AuditLog::deinit(); // release audit context

    return EXIT_SUCCESS;
}
