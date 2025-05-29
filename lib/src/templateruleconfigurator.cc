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

#include "templateruleconfigurator.h"
#include "autoconfig.h"

#include <fty_log.h>
#include <fty_proto.h>
#include <fty_shm.h>
#include <cxxtools/directory.h>
#include <fstream>
#include <algorithm>

bool gDisable_ruleXphaseIsApplicable{false}; // PQSWMBT-4921, to pass selftest (require autoconfig)

// PQSWMBT-4921: Instanciate/expose Xphase rule *only* for Xphase device
// If the rule is a Xphase rule (1ph/3ph):
//      if the asset match the rule, return true,
//      else returns false.
// else return true.
// Note: based on asset ext. attributes if assetInfo is not empty
//       else based on shared (un)available metrics.
bool ruleXphaseIsApplicable(const std::string& ruleName, const AutoConfigurationInfo& assetInfo)
{
    if (gDisable_ruleXphaseIsApplicable) {
        return true; // pass selftest
    }

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
            isAppl = (assetInfo.getAttr("phases.input") == "1");
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
            isAppl = (assetInfo.getAttr("phases.input") == "3");
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
            isAppl = (assetInfo.getAttr("phases.input") == "1");
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
            isAppl = (assetInfo.getAttr("phases.input") == "3");
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
            // exception for epdu: no phases.output available, assume: phases.input == phases.output
            if (ruleName.find("@epdu-") != std::string::npos)
                isAppl = (assetInfo.getAttr("phases.input") == "3");
            else
                isAppl = (assetInfo.getAttr("phases.output") == "3");
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

bool TemplateRuleConfigurator::configure (
    const std::string& name,
    const AutoConfigurationInfo& info,
    const std::string &ename_la,
    mlm_client_t *client
)
{
    log_debug("TemplateRuleConfigurator::configure (name = '%s', info.type = '%s', info.subtype = '%s')",
        name.c_str(), info.type.c_str(), info.subtype.c_str());

    if ((info.operation == FTY_PROTO_ASSET_OP_CREATE)
        || (info.operation == FTY_PROTO_ASSET_OP_UPDATE)
    ) {
        bool fast_track = false;
        std::string port, severity, normal_state, model, iname_la, ename;
        {
            #define ATTVAL(key, defval) ((info.attributes.count(key) != 0) ? info.attributes.at(key) : defval)

            fast_track = ATTVAL("fast_track", "") == "true";
            port = ATTVAL("port", "");
            severity = ATTVAL("alarm_severity", "");
            normal_state = ATTVAL("normal_state", "");
            model = ATTVAL("model", "");
            iname_la = ATTVAL("logical_asset", "");
            ename = ATTVAL("name", "");

            #undef ATTVAL

            if (!port.empty()) { port = "GPI" + port; }
        }

        std::string rule_result = severity;
        std::transform(rule_result.begin(), rule_result.end(), rule_result.begin(), ::tolower);

        // dictionary of tokens replacement
        const std::map<std::string, std::string> dict = {
            { "__ename__", ename },
            { "__logicalasset_iname__", iname_la },
            { "__logicalasset__", ename_la },
            { "__name__", name },
            { "__normalstate__", normal_state },
            { "__port__", port },
            { "__rule_result__", rule_result },
            { "__severity__", severity },
        };

        std::vector<std::string> templates = loadTemplates(info.type, info.subtype, fast_track);

        bool result = true;
        for (const auto& templat : templates) {
            // extra check for sensorgpio
            if (info.subtype == "sensorgpio") {
                if (!isModelOk(model, templat)) {
                    log_debug("Skip rule for gpio: %s", name.c_str());
                    continue;
                }
                else {
                    log_debug("Ready to send rule for gpio: %s", name.c_str());
                }
            }

            // generate the rule from the template
            const std::string rule = replaceTokens(templat, dict);

            log_debug("Sending rule for %s\n%s", name.c_str(), rule.c_str());
            result &= sendNewRule(rule, client);
        }

        return result;
    }
    else {
        log_info("Unhandled operation '%s' on asset '%s'", info.operation.c_str(), name.c_str());
    }

    return true;
}

bool TemplateRuleConfigurator::isModelOk(const std::string& model, const std::string& templat) const
{
    return (templat.find(model) != std::string::npos);
}

bool TemplateRuleConfigurator::isApplicable(const AutoConfigurationInfo& info)
{
    return checkTemplate(info.type, info.subtype);
}

bool TemplateRuleConfigurator::isApplicable(const AutoConfigurationInfo& info, const std::string& templat_name)
{
    const std::string type_name{convertTypeSubType2Name(info.type.c_str(),info.subtype.c_str())};

    if (templat_name.find(type_name) == std::string::npos) {
        return false; // no match
    }

    cxxtools::Directory dir(Autoconfig::RuleFilePath);
    std::ifstream file(dir.path() + "/" + templat_name);
    if (!file.good()) {
        return false; // bad file
    }

    if ((info.subtype == "sensorgpio")
        && (info.attributes.count("model") != 0)
    ) {
        // for sensor gpio, we need to parse the template content to check model
        const std::string templat((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

        const std::string model = info.attributes.at("model");
        if (!isModelOk(model, templat)) {
            return false; // model not found
        }
    }

    return true;
}

bool TemplateRuleConfigurator::templateDirExists() const
{
    if (cxxtools::Directory::exists(Autoconfig::RuleFilePath)) {
        return true;
    }

    log_warning("'%s' directory does not exist", Autoconfig::RuleFilePath.c_str());
    return false;
}

std::vector<std::string> TemplateRuleConfigurator::loadTemplates(const std::string& type, const std::string& subtype, bool fast_track) const
{
    if (!templateDirExists()) {
        return {};
    }

    const std::string type_name{convertTypeSubType2Name(type, subtype)};

    std::vector<std::string> templates;

    cxxtools::Directory dir(Autoconfig::RuleFilePath);
    for (const auto& fn : dir) {
        if (fn.find(type_name) == std::string::npos) {
            continue; // no match
        }

        if (fast_track) {
            if (fn == "realpower.default@__datacenter__.rule") {
                log_debug("match %s but not use for fast track", fn.c_str());
                continue;
            }
        }

        log_debug("match %s", fn.c_str());

        // read the template rule from the file
        std::ifstream file(dir.path() + "/" + fn);
        std::string templat((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

        templates.push_back(templat);
    }

    return templates;
}

std::vector<std::pair<std::string, std::string>> TemplateRuleConfigurator::loadAllTemplates() const
{
    if (!templateDirExists()) {
        return {};
    }

    cxxtools::Directory dir(Autoconfig::RuleFilePath);
    log_info("Load templates from %s", dir.path().c_str());

    std::vector<std::pair<std::string, std::string>> templates;

    for (const auto& fn : dir) {
        if ((fn == ".") || (fn == "..")) { continue; }

        try {
            // read the template rule from the file
            std::ifstream file(dir.path() + "/" + fn);
            std::string templat((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

            templates.push_back(std::make_pair(fn, templat));
        }
        catch (const std::exception& e) {
            log_error("Load failed: %s/%s (e: %s)", dir.path().c_str(), fn.c_str(), e.what());
        }
    }
    return templates;
}

bool TemplateRuleConfigurator::checkTemplate(const std::string& type, const std::string& subtype) const
{
    if (!templateDirExists()) {
        return false;
    }

    const std::string type_name{convertTypeSubType2Name(type, subtype)};

    cxxtools::Directory dir(Autoconfig::RuleFilePath);
    for (const auto& fn : dir) {
        if (fn.find(type_name) != std::string::npos) {
            log_debug("Using template '%s'", fn.c_str());
            return true;
        }
    }
    return false;
}

std::string TemplateRuleConfigurator::convertTypeSubType2Name(const std::string& type, const std::string& subtype) const
{
    static const std::string prefix{"__"};

    if (subtype.empty()
        || (subtype == "unknown")
        || (subtype == "N_A")) {
        return prefix + type + prefix; // ex: __rack__
    }
    return prefix + type + "_" + subtype + prefix; // ex: __device_ups__
}

std::string TemplateRuleConfigurator::replaceTokens(const std::string& text, const std::map<std::string, std::string>& dict) const
{
    std::string result{text};

    for (const auto& it : dict) {
        const std::string& token{it.first};
        const std::string& value{it.second};

        size_t pos = 0;
        while ((pos = result.find(token, pos)) != std::string::npos) {
            result.replace(pos, token.length(), value);
            pos += value.length();
        }
    }
    return result;
}
