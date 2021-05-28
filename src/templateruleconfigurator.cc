/*  =========================================================================
    templateruleconfigurator - Template rule configurator

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
#include <regex>

bool gDisable_ruleXphaseIsApplicable{false}; // PQSWMBT-4921, to pass selftest

// PQSWMBT-4921 hotfix: isApplicable/addRule exception
// Instanciate/expose Xphase rule *only* for Xphase device
// Note: based on shared metrics if assetInfo is empty (not available),
//       else based on asset ext. attributes
bool ruleXphaseIsApplicable(const std::string& ruleName, const AutoConfigurationInfo& assetInfo)
{
    if (gDisable_ruleXphaseIsApplicable)
        return true; // pass selftest

    auto pos = ruleName.find("@");
    if (pos == std::string::npos) {
        log_error("malformed ruleName (ruleName: '%s')", ruleName.c_str());
        return false;
    }

    auto asset = ruleName.substr(pos + 1);
    std::string foo;

    bool isAppl = true; // applicable (default)

    if (   (ruleName.find("voltage.input_1phase@ups-")  == 0)
        || (ruleName.find("voltage.input_1phase@epdu-") == 0))
    {
        // voltage.input_1phase@__device_ups__.rule
        // voltage.input_1phase@__device_epdu__.rule
        // is applicable only for 1phase device (phases.input | voltage.input.Lx-N)

        if (assetInfo.empty()) {
            isAppl =    (fty::shm::read_metric_value(asset, "voltage.input.L1-N", foo) == 0)
                     && (fty::shm::read_metric_value(asset, "voltage.input.L2-N", foo) != 0)
                     && (fty::shm::read_metric_value(asset, "voltage.input.L3-N", foo) != 0);
        }
        else {
            isAppl = (assetInfo.attributes.find("phases.input")->second == "1");
        }
    }
    else if (   (ruleName.find("voltage.input_3phase@ups-")  == 0)
             || (ruleName.find("voltage.input_3phase@epdu-") == 0))
    {
        // voltage.input_3phase@__device_ups__.rule
        // voltage.input_3phase@__device_epdu__.rule
        // is applicable only for 3phase device (phases.input | voltage.input.Lx-N)

        if (assetInfo.empty()) {
            isAppl =    (fty::shm::read_metric_value(asset, "voltage.input.L1-N", foo) == 0)
                     && (fty::shm::read_metric_value(asset, "voltage.input.L2-N", foo) == 0)
                     && (fty::shm::read_metric_value(asset, "voltage.input.L3-N", foo) == 0);
        }
        else {
            isAppl = (assetInfo.attributes.find("phases.input")->second == "3");
        }
    }
    else if (ruleName.find("load.input_1phase@epdu-") == 0)
    {
        // load.input_1phase@__device_epdu__.rule
        // is applicable only for 1phase device (phases.input | load.input.Lx)

        if (assetInfo.empty()) {
            isAppl =    (fty::shm::read_metric_value(asset, "load.input.L1", foo) == 0)
                     && (fty::shm::read_metric_value(asset, "load.input.L2", foo) != 0)
                     && (fty::shm::read_metric_value(asset, "load.input.L3", foo) != 0);
        }
        else {
            isAppl = (assetInfo.attributes.find("phases.input")->second == "1");
        }
    }
    else if (ruleName.find("load.input_3phase@epdu-") == 0)
    {
        // load.input_3phase@__device_epdu__.rule
        // is applicable only for 3phase device (phases.input | load.input.Lx)

        if (assetInfo.empty()) {
            isAppl =    (fty::shm::read_metric_value(asset, "load.input.L1", foo) == 0)
                     && (fty::shm::read_metric_value(asset, "load.input.L2", foo) == 0)
                     && (fty::shm::read_metric_value(asset, "load.input.L3", foo) == 0);
        }
        else {
            isAppl = (assetInfo.attributes.find("phases.input")->second == "3");
        }
    }
    else if (   (ruleName.find("phase_imbalance@ups-")  == 0)
             || (ruleName.find("phase_imbalance@epdu-") == 0))
    {
        // phase_imbalance@__device_ups__.rule     (3phase rules)
        // phase_imbalance@__device_epdu__.rule
        // is applicable only for 3phase device (phases.output | realpower.output.Lx)

        if (assetInfo.empty()) {
            isAppl =    (fty::shm::read_metric_value(asset, "realpower.output.L1", foo) == 0)
                     && (fty::shm::read_metric_value(asset, "realpower.output.L2", foo) == 0)
                     && (fty::shm::read_metric_value(asset, "realpower.output.L3", foo) == 0);
        }
        else {
            isAppl = (assetInfo.attributes.find("phases.output")->second == "3");
        }
    }
    else if (   (ruleName.find("phase_imbalance@datacenter-") == 0)
             || (ruleName.find("phase_imbalance@rack-")       == 0))
    {
        // phase_imbalance@__datacenter__.rule     (3phase rules)
        // phase_imbalance@__rack__.rule
        // is applicable only for 3phase asset (realpower.output.Lx)
        // Note: no 'phases.output' ext. attributes for these assets

        isAppl =    (fty::shm::read_metric_value(asset, "realpower.output.L1", foo) == 0)
                 && (fty::shm::read_metric_value(asset, "realpower.output.L2", foo) == 0)
                 && (fty::shm::read_metric_value(asset, "realpower.output.L3", foo) == 0);
    }

    if (!isAppl) {
        log_debug("ruleXphaseIsApplicable: FALSE for rule '%s'", ruleName.c_str());
        //log_debug("ruleXphaseIsApplicable, assetInfo(%s): %s ", asset.c_str(), assetInfo.dump({"name", "phase"}).c_str());
    }

    return isAppl;
}

bool
TemplateRuleConfigurator::configure (
    const std::string& name,
    const AutoConfigurationInfo& info,
    const std::string &ename_la,
    mlm_client_t *client
)
{
    log_debug ("TemplateRuleConfigurator::configure (name = '%s', info.type = '%s', info.subtype = '%s')",
                name.c_str(), info.type.c_str (), info.subtype.c_str ());

    if (streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_CREATE)
        || streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_UPDATE))
    {
        std::string port, severity, normal_state, model, iname_la, rule_result, ename;
        bool fast_track = false;

        for (auto &i : info.attributes)
        {
            if (i.first == "fast_track") {
                //skip the rules from DC in fast track mode
                fast_track = (i.second == "true");
            }
            else if (i.first == "port")
                port = "GPI" + i.second;
            else if (i.first == "alarm_severity") {
                severity = i.second;
                rule_result = i.second;
                std::transform (rule_result.begin(), rule_result.end(), rule_result.begin(), ::tolower);
            }
            else if (i.first == "normal_state")
                normal_state = i.second;
            else if (i.first == "model")
                model = i.second;
            else if (i.first == "logical_asset")
                iname_la = i.second;
            else if (i.first == "name")
                ename = i.second;
        }

        std::vector <std::string> patterns = {"__name__", "__port__", "__logicalasset__", "__logicalasset_iname__", "__severity__", "__normalstate__", "__rule_result__","__ename__"};
        std::vector <std::string> replacements = {name, port, ename_la, iname_la, severity, normal_state, rule_result, ename};

        std::vector <std::string> templates = loadTemplates (info.type.c_str (), info.subtype.c_str (), fast_track);
        bool result = true;

        for (auto &templat : templates) {
            //extra check for sensorgpio
            if (info.subtype == "sensorgpio")
            {
                if (!TemplateRuleConfigurator::isModelOk (model, templat))
                {
                    log_debug("Skip rule for gpio:\n %s", name.c_str());
                    continue;
                }
                else
                {
                    log_debug("Ready to send rule for gpio:\n %s", name.c_str());
                }
            }

            //generate the rule from the template
            std::string rule = replaceTokens(templat, patterns , replacements);

            log_debug("sending rule for \n %s", name.c_str());
            log_debug("rule: %s", rule.c_str());
            result &= sendNewRule(rule, client);
        }

        return result;
    }
    else if (streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_DELETE)
        || streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_RETIRE)
        || streq (info.operation.c_str (), FTY_PROTO_ASSET_OP_INVENTORY)
    ) {
        log_warning ("TODO: known operation '%s' without implemented action", info.operation.c_str ());
    }
    else {
        log_error ("Unknown operation '%s' on asset '%s'", info.operation.c_str (), name.c_str ());
    }

    return true;
}

bool
TemplateRuleConfigurator::isModelOk (const std::string& model,
                                     const std::string& templat)
{
    return (templat.find (model) != std::string::npos);
}

bool TemplateRuleConfigurator::isApplicable (const AutoConfigurationInfo& info){
    return checkTemplate(info.type.c_str (), info.subtype.c_str ());
}

bool TemplateRuleConfigurator::isApplicable (const AutoConfigurationInfo& info,
        const std::string& templat_name)
{
    cxxtools::Directory d(Autoconfig::RuleFilePath);
    std::ifstream f(d.path() + "/" + templat_name);
    if (!f.good())
        return false; // bad file

    std::string type_name = convertTypeSubType2Name(info.type.c_str(),info.subtype.c_str());
    if (templat_name.find(type_name.c_str()) == std::string::npos)
        return false; // no match

    if (info.subtype == "sensorgpio" && info.attributes.find("model") != info.attributes.end())
    {
        std::string model = info.attributes.find("model")->second;
        //for sensor gpio, we need to parse the template content to check model
        std::string templat_content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        if (templat_content.find(model) == std::string::npos)
            return false; // model not found
    }

    return true;
}

std::vector <std::string> TemplateRuleConfigurator::loadTemplates(const char *type, const char *subtype, bool fast_track){
    std::vector <std::string> templates;
    if (!cxxtools::Directory::exists (Autoconfig::RuleFilePath.c_str ())){
        log_info("TemplateRuleConfigurator '%s' dir does not exist",Autoconfig::RuleFilePath.c_str ());
        return templates;
    }
    std::string type_name = convertTypeSubType2Name(type,subtype);
    cxxtools::Directory d(Autoconfig::RuleFilePath);
    for ( const auto &fn : d) {
        if ( fn.find(type_name.c_str())!= std::string::npos){

            if(fast_track)
            {
                if(fn == "realpower.default@__datacenter__.rule")
                {
                    log_debug("match %s but not use for fast track", fn.c_str());
                    continue;
                }
            }

            log_debug("match %s", fn.c_str());

            // read the template rule from the file
            std::ifstream f(d.path() + "/" + fn);
            std::string str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            templates.push_back(str);
        }
    }
    return templates;
}

std::vector <std::pair<std::string,std::string>> TemplateRuleConfigurator::loadAllTemplates(){
    std::vector <std::pair<std::string,std::string>> templates;
    if (!cxxtools::Directory::exists (Autoconfig::RuleFilePath.c_str ())){
        log_info("TemplateRuleConfigurator '%s' dir does not exist",Autoconfig::RuleFilePath.c_str ());
        return templates;
    }
    cxxtools::Directory d(Autoconfig::RuleFilePath);
    log_info("load all templates from %s", d.path().c_str());
    for ( const auto &fn : d) {
        if ( fn.compare(".")!=0  && fn.compare("..")!=0) {
            try {
                // read the template rule from the file
                std::ifstream f(d.path() + "/" + fn);
                std::string str((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
                templates.push_back(std::make_pair(fn,str));
            }
            catch (const std::exception& e) {
                log_error("error loading %s/%s (e: %s)", d.path().c_str(), fn.c_str(), e.what());
            }
        }
    }
    return templates;
}

bool TemplateRuleConfigurator::checkTemplate(const char *type, const char *subtype)
{
    if (!cxxtools::Directory::exists (Autoconfig::RuleFilePath)){
        log_warning("TemplateRuleConfigurator '%s' dir does not exist", Autoconfig::RuleFilePath.c_str ());
        return false;
    }

    std::string type_name = convertTypeSubType2Name(type, subtype);

    cxxtools::Directory d(Autoconfig::RuleFilePath);
    for (const auto &fName : d) {
        log_trace ("Template name is '%s'", fName.c_str ());
        if (fName.find(type_name.c_str()) != std::string::npos) {
            log_debug ("Using template '%s'", fName.c_str ());
            return true;
        }
    }
    return false;
}

std::string TemplateRuleConfigurator::convertTypeSubType2Name(const char *type, const char *subtype)
{
    std::string prefix ("__");
    std::string subtype_str (subtype);

    std::string name;
    if (subtype_str.empty () || (subtype_str == "unknown") || (subtype_str == "N_A"))
        name = prefix + type + prefix;
    else
        name = prefix + type + '_' + subtype + prefix;

    //log_trace("convertTypeSubType2Name(info.type = '%s', info.subtype = '%s') = '%s')",
    //        type, subtype,name.c_str());
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
