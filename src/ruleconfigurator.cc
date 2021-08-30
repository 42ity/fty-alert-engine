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
//#include <regex>
#include <cxxtools/regex.h>

bool RuleConfigurator::sendNewRule(const std::string& rule, mlm_client_t* client)
{
    if (!client)
        return false;

    zmsg_t* message = zmsg_new();
    zmsg_addstr(message, "ADD");
    zmsg_addstr(message, rule.c_str());

    const char* dest = Autoconfig::AlertEngineName.c_str();

    // CAUTION: regression issue "std::regex don't match 'flexible' rule"
    //std::regex reg("^[[:blank:][:cntrl:]]*\\{[[:blank:][:cntrl:]]*\"flexible\"", std::regex::extended);
    //if (std::regex_match(rule, reg))
    //    dest = "fty-alert-flexible";

    cxxtools::Regex reg("^[[:blank:][:cntrl:]]*\\{[[:blank:][:cntrl:]]*\"flexible\"", REG_EXTENDED);
    if (reg.match(rule))
        dest = "fty-alert-flexible";

    const char* subject = "rfc-evaluator-rules";
    log_debug("Sending '%s/ADD' to '%s'", subject, dest);

    if (mlm_client_sendto(client, dest, subject, NULL, 5000, &message) != 0) {
        log_error("mlm_client_sendto (address = '%s', subject = '%s', timeout = '5000') failed.", dest,
            subject);
        return false;
    }
    return true;
}
