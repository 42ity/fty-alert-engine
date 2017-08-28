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

bool
TemplateRuleConfigurator::configure (const std::string& name, const AutoConfigurationInfo& info, mlm_client_t *client){
    zsys_debug ("TemplateRuleConfigurator::configure (name = '%s', info.type = '%s', info.subtype = '%s')",
            name.c_str(), info.type.c_str (), info.subtype.c_str ());
    if (streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_CREATE) || streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_UPDATE)) {
                bool result = true;
                std::vector <std::string> templates = loadTemplates (info.type.c_str (), info.subtype.c_str ());

                std::string port, logical_asset, severity, normal_state, model, ename_la ;

                for (auto &i : info.attributes)
                {
                    if (i.first == "port")
                        port = "GPI" + i.second;
                    else
                    if (i.first == "logical_asset")
                    {
                        logical_asset = i.second;
                        ename_la = TemplateRuleConfigurator::reqEname (logical_asset, client);
                    }
                    else
                    if (i.first == "alarm_severity")
                        severity = i.second;
                    else
                    if (i.first == "normal_state")
                        normal_state = i.second;
                    else
                    if (i.first == "model")
                        model = i.second;
                }

                if (ename_la.empty ())
                    ename_la = logical_asset;

                std::vector <std::string> patterns = {"__name__", "__port__", "__logicalasset__", "__severity__", "__normalstate__"};
                std::vector <std::string> replacements = {name, port, ename_la, severity, normal_state};

                for ( auto &templat : templates) {
                    if (info.subtype == "sensorgpio")
                    {
                        if (TemplateRuleConfigurator::isModelOk (model, templat))
                        {
                            std::string rule=replaceTokens(templat, patterns , replacements);
                            zsys_debug("sending rule for gpio:\n %s", rule.c_str());
                            result &= sendNewRule(rule,client);
                        }
                    }
                    else
                    {
                        std::string rule=replaceTokens(templat, patterns , replacements);
                        zsys_debug("sending rule :\n %s", rule.c_str());
                        result &= sendNewRule(rule,client);
                    }
                }

                return result;
    }
    else if (streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_DELETE) || streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_RETIRE) || streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_INVENTORY)) {
        zsys_warning ("TODO: known operation '%s' without implemented action", info.operation.c_str ());
    }
    else
        zsys_error ("Unknown operation '%s' on asset '%s'", info.operation.c_str (), name.c_str ());
    return true;

}

std::string
TemplateRuleConfigurator::reqEname (const std::string& iname,
                                    mlm_client_t *client)
{
    std::string ename;
    std::string subj = "ENAME_FROM_INAME";

    zmsg_t *req = zmsg_new ();
    zmsg_addstr (req, iname.c_str());

    int rv = mlm_client_sendto (client, "asset-agent", subj.c_str(), NULL, 5000, &req);
    if (rv != 0)
        zsys_error ("reqEname: mlm_client_sendto (address = '%s', subject = '%s', timeout = '5000') failed.",
                    "agent-asset", subj.c_str ());

    zmsg_t *rep = mlm_client_recv (client);
    assert (rep);
    char *status = zmsg_popstr (rep);
    if (streq (status, "OK"))
    {
        char *c_ename = zmsg_popstr(rep);
        ename = c_ename;
    }
    else
    {
        zsys_error ("reqEname: %s for asset %s", zmsg_popstr (rep), iname.c_str());
        ename = "";
    }
    zmsg_destroy (&rep);
    return ename;
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
        zsys_info("TemplateRuleConfigurator '%s' dir does not exist",Autoconfig::RuleFilePath.c_str ());
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
        zsys_info("TemplateRuleConfigurator '%s' dir does not exist",Autoconfig::RuleFilePath.c_str ());
        return false;
    }
    std::string type_name = convertTypeSubType2Name(type,subtype);
    cxxtools::Directory d(Autoconfig::RuleFilePath);
    for ( const auto &fn : d) {
        zsys_debug ("Template name is '%s'", fn.c_str ());
        if ( fn.find(type_name.c_str())!= std::string::npos){
            return true;
        }
    }
    return false;
}

std::string TemplateRuleConfigurator::convertTypeSubType2Name(const char *type, const char *subtype){
    std::string name;
    std::string prefix ("__");
    std::string subtype_str (subtype);
    if (subtype_str.empty () || (subtype_str == "unknown"))
        name = prefix + type + prefix;
    else
        name = prefix + type + '_' + subtype + prefix;
    zsys_debug("convertTypeSubType2Name(info.type = '%s', info.subtype = '%s') = '%s')",
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
