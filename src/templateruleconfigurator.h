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

#ifndef TEMPLATERULECONFIGURATOR_H_INCLUDED
#define TEMPLATERULECONFIGURATOR_H_INCLUDED

#include <string>
#include <fstream>

#include "ruleconfigurator.h"


class TemplateRuleConfigurator : public RuleConfigurator {
    public:
        bool configure (const std::string& name,
                        const AutoConfigurationInfo& info,
                        const std::string &logical_asset,
                        mlm_client_t *client);
        bool isApplicable (const AutoConfigurationInfo& info);
        std::vector <std::pair<std::string,std::string>>  loadAllTemplates();
        virtual ~TemplateRuleConfigurator() {};
    private:
        bool checkTemplate(const char *type, const char *subtype);
        std::vector <std::string> loadTemplates(const char *type, const char *subtype);
        std::string convertTypeSubType2Name(const char *type, const char *subtype);
        std::string replaceTokens( const std::string &text,
                                   const std::vector <std::string> &patterns,
                                   const std::vector <std::string> &replacements) const;
        bool isModelOk (const std::string &model, const std::string &templat);

};

#endif
