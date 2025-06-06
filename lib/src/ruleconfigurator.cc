/*  =========================================================================
    ruleconfigurator - Rule Configurator

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

#include "ruleconfigurator.h"
#include <cxxtools/regex.h>
#include <fty_log.h>

bool RuleConfigurator::sendNewRule(const std::string& rule, mlm_client_t* client)
{
    if (!client) { log_error("client is NULL"); return false; }

    zmsg_t* msg = zmsg_new();
    if (!msg) { log_error("zmsg_new() failed"); return false; }

    zmsg_addstr(msg, "ADD");
    zmsg_addstr(msg, rule.c_str()); //json

    const char* dest = Autoconfig::AlertEngineName.c_str();
    const char* subject = RULES_SUBJECT;

    cxxtools::Regex reg("^[[:blank:][:cntrl:]]*\\{[[:blank:][:cntrl:]]*\"flexible\"", REG_EXTENDED);
    if (reg.match(rule)) {
        dest = "fty-alert-flexible";
    }

    log_debug("Sending '%s/ADD' to '%s'", subject, dest);

    const int timeout_ms = 5000;
    int r = mlm_client_sendto(client, dest, subject, NULL, timeout_ms, &msg);
    zmsg_destroy(&msg);
    // ignore response (no consumption)

    if (r != 0) {
        log_error("mlm_client_sendto() failed (dest = '%s', subject = '%s/ADD', timeout = %d)", dest, subject, timeout_ms);
    }
    return (r == 0);
}
