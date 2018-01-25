/*  =========================================================================
    ruleconfigurator - Rule Configurator

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
    ruleconfigurator - Rule Configurator
@discuss
@end
*/

#include "fty_alert_engine_classes.h"

#include <cstring>
#include <ostream>
#include <limits>
#include <mutex>
#include <cxxtools/jsonformatter.h>
#include <cxxtools/convert.h>
#include <cxxtools/regex.h>
#include <cxxtools/serializationinfo.h>
#include <cxxtools/split.h>

#include <string>
//#include <math.h>

#include "autoconfig.h"
#include "ruleconfigurator.h"

bool RuleConfigurator::sendNewRule (const std::string& rule, mlm_client_t *client)
{
    if (!client)
        return false;
    zmsg_t *message = zmsg_new ();
    zmsg_addstr (message, "ADD");
    zmsg_addstr (message, rule.c_str());

    // is it flexible?
    cxxtools::Regex reg("^[[:blank:][:cntrl:]]*\\{[[:blank:][:cntrl:]]*\"flexible\"", REG_EXTENDED);
    const char *dest = Autoconfig::AlertEngineName.c_str ();
    if (reg.match (rule)) dest = "fty-alert-flexible";

    if (mlm_client_sendto (client, dest, "rfc-evaluator-rules", NULL, 5000, &message) != 0) {
        zsys_error ("mlm_client_sendto (address = '%s', subject = '%s', timeout = '5000') failed.",
                dest, "rfc-evaluator-rules");
        return false;
    }
    return true;
}

