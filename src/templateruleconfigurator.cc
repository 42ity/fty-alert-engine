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

#include <algorithm>
#include <cxxtools/directory.h>
#include "templateruleconfigurator.h"
#include "autoconfig.h"

bool
TemplateRuleConfigurator::configure (const std::string& name, const AutoConfigurationInfo& info, const std::string &ename_la, mlm_client_t *client){
    log_debug ("TemplateRuleConfigurator::configure (name = '%s', info.type = '%s', info.subtype = '%s')",
                name.c_str(), info.type.c_str (), info.subtype.c_str ());
    if (streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_CREATE) || streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_UPDATE)) {
                bool result = true;
                std::vector <std::string> templates = loadTemplates (info.type.c_str (), info.subtype.c_str ());

                std::string port, severity, normal_state, model, iname_la, rule_result, ename;

                for (auto &i : info.attributes)
                {
                    if (i.first == "port")
                        port = "GPI" + i.second;
                    else
                    if (i.first == "alarm_severity") {
                        severity = i.second;
                        rule_result = i.second;
                        std::transform (rule_result.begin(), rule_result.end(), rule_result.begin(), ::tolower);
                    }
                    else
                    if (i.first == "normal_state")
                        normal_state = i.second;
                    else
                    if (i.first == "model")
                        model = i.second;
                    else
                    if (i.first == "logical_asset")
                        iname_la = i.second;
                    else
                    if (i.first == "name")
                        ename = i.second;
                }

                std::vector <std::string> patterns = {"__name__", "__port__", "__logicalasset__", "__logicalasset_iname__", "__severity__", "__normalstate__", "__rule_result__","__ename__"};
                std::vector <std::string> replacements = {name, port, ename_la, iname_la, severity, normal_state, rule_result, ename};

                for ( auto &templat : templates) {
                    if (info.subtype == "sensorgpio")
                    {
                        if (TemplateRuleConfigurator::isModelOk (model, templat))
                        {
                            std::string rule=replaceTokens(templat, patterns , replacements);
                            log_debug("sending rule for gpio:\n %s", rule.c_str());
                            result &= sendNewRule(rule,client);
                        }
                    }
                    else
                    {
                        std::string rule=replaceTokens(templat, patterns , replacements);
                        log_debug("sending rule for \n %s", name.c_str());
                        log_trace ("rule: %s", rule.c_str());
                        result &= sendNewRule(rule,client);
                    }
                }

                return result;
    }
    else if (streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_DELETE) || streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_RETIRE) || streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_INVENTORY)) {
        log_warning ("TODO: known operation '%s' without implemented action", info.operation.c_str ());
    }
    else
        log_error ("Unknown operation '%s' on asset '%s'", info.operation.c_str (), name.c_str ());
    return true;

}

bool
TemplateRuleConfigurator::isModelOk (const std::string& model,
                                     const std::string& templat)
{
    if (templat.find (model) != std::string::npos)
        return true;
    else
        return false;
}

bool TemplateRuleConfigurator::isApplicable (const AutoConfigurationInfo& info){
    return checkTemplate(info.type.c_str (), info.subtype.c_str ());
}

std::vector <std::string> TemplateRuleConfigurator::loadTemplates(const char *type, const char *subtype){
    std::vector <std::string> templates;
    if (!cxxtools::Directory::exists (Autoconfig::RuleFilePath.c_str ())){
        log_info("TemplateRuleConfigurator '%s' dir does not exist",Autoconfig::RuleFilePath.c_str ());
        return templates;
    }
    std::string type_name = convertTypeSubType2Name(type,subtype);
    cxxtools::Directory d(Autoconfig::RuleFilePath);
    for ( const auto &fn : d) {
        if ( fn.find(type_name.c_str())!= std::string::npos){
            log_debug("match %s", fn.c_str());
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
        log_warning("TemplateRuleConfigurator '%s' dir does not exist",Autoconfig::RuleFilePath.c_str ());
        return false;
    }
    std::string type_name = convertTypeSubType2Name(type,subtype);
    cxxtools::Directory d(Autoconfig::RuleFilePath);
    for ( const auto &fn : d) {
        log_trace ("Template name is '%s'", fn.c_str ());
        if ( fn.find(type_name.c_str())!= std::string::npos){
            log_debug ("Using template '%s'", fn.c_str ());
            return true;
        }
    }
    return false;
}

std::string TemplateRuleConfigurator::convertTypeSubType2Name(const char *type, const char *subtype){
    std::string name;
    std::string prefix ("__");
    std::string subtype_str (subtype);
    if (subtype_str.empty () || (subtype_str == "unknown") || (subtype_str == "N_A"))
        name = prefix + type + prefix;
    else
        name = prefix + type + '_' + subtype + prefix;
    log_debug("convertTypeSubType2Name(info.type = '%s', info.subtype = '%s') = '%s')",
            type, subtype,name.c_str());
    return name;
}

std::string
TemplateRuleConfigurator::replaceTokens (
    const std::string &text,
    const std::vector <std::string> &patterns,
    const std::vector <std::string> &replacements) const
{
    assert (patterns.size () == replacements.size());
    int i = 0;
    std::string result = text;

    for ( auto &p : patterns)
    {
        size_t pos = 0;
        while (( pos = result.find (p, pos)) != std::string::npos){
            result.replace (pos, p.length(), replacements.at (i));
            pos += replacements.at (i).length ();
        }
        ++i;
    }

    return result;
}
