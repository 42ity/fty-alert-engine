/*  =========================================================================
    templateruleconfigurator - Template rule configurator

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
    templateruleconfigurator - Template rule configurator
@discuss
@end
*/

#include "fty_alert_engine_classes.h"

#include <cxxtools/directory.h>
#include "templateruleconfigurator.h"
#include "autoconfig.h"

bool TemplateRuleConfigurator::configure (const std::string& name, const AutoConfigurationInfo& info, mlm_client_t *client){
    zsys_debug ("TemplateRuleConfigurator::configure (name = '%s', info.type = '%" PRIi32"', info.subtype = '%" PRIi32"')",
            name.c_str(), info.type, info.subtype);
    if (streq (info.operation, FTY_PROTO_ASSET_OP_CREATE) || streq (info.operation, FTY_PROTO_ASSET_OP_UPDATE)) {
                bool result = true;
                std::vector <std::string> templates = loadTemplates(info.type, info.subtype);
                for ( auto &templat : templates) {
                    std::string rule=replaceTokens(templat,"__name__",name);
                    zsys_debug("sending rule :\n %s", rule.c_str());
                    result &= sendNewRule(rule,client);
                }   

                return result;
    }
    else if (streq (info.operation, FTY_PROTO_ASSET_OP_DELETE) || streq (info.operation, FTY_PROTO_ASSET_OP_RETIRE) || streq (info.operation, FTY_PROTO_ASSET_OP_INVENTORY)) {
        zsys_warning ("TODO: known operation '%s' without implemented action", info.operation);
    } 
    else
        zsys_error ("Unknown operation '%s' on asset '%s'", info.operation, name.c_str ());
    return true;

}

bool TemplateRuleConfigurator::isApplicable (const AutoConfigurationInfo& info){
        return checkTemplate(info.type, info.subtype);
}           

std::vector <std::string> TemplateRuleConfigurator::loadTemplates(const char *type, const char *subtype){
    std::vector <std::string> templates;
    if (!cxxtools::Directory::exists (Autoconfig::RuleFilePath)){
        zsys_info("TemplateRuleConfigurator '%s' dir does not exist",Autoconfig::RuleFilePath);
        return templates;
    }
    std::string type_name = convertTypeSubType2Name(type,subtype);
    cxxtools::Directory d(Autoconfig::RuleFilePath);
    for ( const auto &fn : d) {
        if ( fn.find(type_name.c_str())!= std::string::npos){
            zsys_debug("match %s", fn.c_str());
            // read the template rule from the file
            std::ifstream f(d.path() + "/" + fn);
            std::string str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            templates.push_back(str);
        }
    }       
    return templates;
}           

bool TemplateRuleConfigurator::checkTemplate(const char *type, const char *subtype){
    if (!cxxtools::Directory::exists (Autoconfig::RuleFilePath)){
        zsys_info("TemplateRuleConfigurator '%s' dir does not exist",Autoconfig::RuleFilePath);
        return false;
    }
    std::string type_name = convertTypeSubType2Name(type,subtype);
    cxxtools::Directory d(Autoconfig::RuleFilePath);
    for ( const auto &fn : d) {
        if ( fn.find(type_name.c_str())!= std::string::npos){
            return true;
        }
    }
    return false;
}
                                                               
std::string TemplateRuleConfigurator::convertTypeSubType2Name(const char *type, const char *subtype){
    std::string name;
    std::string prefix ("__");
    if (subtype != NULL)
        name = prefix + type + '_' + subtype + prefix;
    else
        name = prefix + type + prefix;
    zsys_debug("convertTypeSubType2Name(info.type = '%s', info.subtype = '%s' = '%s')",
            type, subtype,name.c_str());
    return name;
}

std::string TemplateRuleConfigurator::replaceTokens( const std::string &text, const std::string &pattern, const std::string &replacement) const{
    std::string result = text;
    size_t pos = 0;
    while( ( pos = result.find(pattern, pos) ) != std::string::npos){
        result.replace(pos, pattern.length(), replacement);
        pos += replacement.length();
    }
    return result;
}

