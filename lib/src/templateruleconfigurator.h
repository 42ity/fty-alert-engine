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

#pragma once

#include "ruleconfigurator.h"
#include <string>
#include <vector>
#include <map>

// PQSWMBT-4921 Xphase rule exceptions
extern bool gDisable_ruleXphaseIsApplicable; // to pass selftest
bool ruleXphaseIsApplicable(const std::string& ruleName, const AutoConfigurationInfo& assetInfo);

class TemplateRuleConfigurator : public RuleConfigurator
{
public:
    virtual ~TemplateRuleConfigurator(){};

    using RuleConfigurator::configure;

    bool configure(const std::string& name, const AutoConfigurationInfo& info, const std::string& logical_asset, mlm_client_t* client);
    bool isApplicable(const AutoConfigurationInfo& info);
    bool isApplicable(const AutoConfigurationInfo& info, const std::string& templat_name);

    std::vector<std::pair<std::string, std::string>> loadAllTemplates() const;

private:
    bool templateDirExists() const;
    bool checkTemplate(const std::string& type, const std::string& subtype) const;
    std::vector<std::string> loadTemplates(const std::string& type, const std::string& subtype, bool fast_track) const;

    bool isModelOk(const std::string& model, const std::string& templat) const;
    std::string convertTypeSubType2Name(const std::string& type, const std::string& subtype) const;
    std::string replaceTokens(const std::string& text, const std::map<std::string, std::string>& dict) const;
};
