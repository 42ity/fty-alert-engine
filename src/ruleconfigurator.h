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

#ifndef RULECONFIGURATOR_H_INCLUDED
#define RULECONFIGURATOR_H_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <string>
#include <string>
#include <map>
#include <vector>

#include <malamute.h>

#include "preproc.h"



class RuleConfigurator {
  public:
    virtual bool configure (const std::string& name, const AutoConfigurationInfo& info, const std::string &logical_asset)
    {
        return configure (name, info, logical_asset, NULL);
    }

    virtual bool configure (const std::string& name, const AutoConfigurationInfo& info, const std::string &logical_asset, mlm_client_t *client)
    {
        return false;
    }
    virtual bool isApplicable (UNUSED_PARAM const AutoConfigurationInfo& info)
    {
        return false;
    }

    bool sendNewRule (const std::string& rule, mlm_client_t *client);

    std::string makeThresholdRule (
          const std::string& rule_name,
          std::vector<std::string> topic_specification,
          const std::string& element_name,
          //          value         action_1, ..., action_N   severity     description
          std::tuple <std::string, std::vector <std::string>, std::string, std::string> low_critical,
          std::tuple <std::string, std::vector <std::string>, std::string, std::string> low_warning,
          std::tuple <std::string, std::vector <std::string>, std::string, std::string> high_warning,
          std::tuple <std::string, std::vector <std::string>, std::string, std::string> high_critical,
          const char *lua_function);

    std::string makeSingleRule (
          const std::string& rule_name,
          const std::vector<std::string>& target,
          const std::string& element_name,
          //                          value_name   value
          const std::vector <std::pair<std::string, std::string>>& values,
          //                           result_name               actions       severity     description
          const std::vector <std::tuple<std::string, std::vector <std::string>, std::string, std::string>>& results,
          const std::string& evaluation);

    std::string makeSingleRule_results (std::tuple<std::string, std::vector <std::string>, std::string, std::string> result);

  // TODO:
  // provide prepared methods for two remaining rule types
  //      makeSingleRule
  //      makePatternRule

    virtual ~RuleConfigurator() {};

};

#ifdef __cplusplus
}
#endif

#endif
