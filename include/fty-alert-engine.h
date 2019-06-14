/*  =========================================================================
    fty-alert-engine - 42ity service evaluating rules written in Lua and producing alerts

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

#ifndef FTY_ALERT_ENGINE_H_H_INCLUDED
#define FTY_ALERT_ENGINE_H_H_INCLUDED

//  Include the project library file
#include "fty_alert_engine_library.h"

//  Add your own public definitions here, if you need them
static const char * RULES_SUBJECT = "rfc-evaluator-rules";
static const char * LIST_RULE_MB = "RULE_HANDLING";

/// config path
static const char *CONFIG_FILE = "/etc/fty-alert-engine/fty-alert-engine.cfg";
/// path to the directory, where rules are stored. Attention: without last slash!
static const char *RULE_PATH_DEFAULT = "/var/lib/fty/fty-alert-engine";
/// path to the directory, where templates are stored. Attention: without last slash!
static const char *TEMPLATE_PATH_DEFAULT = "/usr/share/bios/fty-autoconfig";
/// default timeout [ms]
static const char *DEFAULT_TIMEOUT = "30000";

/// trigger name
static const char *TRIGGER_AGENT_NAME_MAILBOX = "fty-alert-trigger";
static const char *TRIGGER_AGENT_NAME_STREAM = "fty-alert-trigger-stream";

/// config name
static const char *CONFIG_AGENT_NAME = "fty-alert-config";

/// list name
static const char *LIST_AGENT_NAME = "fty-alert-list";

/// malamute endpoint
static const char *ENDPOINT = "ipc://@/malamute";

#endif
