/*  =========================================================================
    extended_rules - Rule classes implementation

    Copyright (C) 2019 - 2019 Eaton

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
    extended_rules - Rule classes implementation
@discuss
@end
*/

#include <cxxtools/jsondeserializer.h>
#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <functional>

#include "fty_alert_engine_classes.h"

Rule::VectorVectorStrings evaluate_helper (
        const Rule::VectorStrings &metrics,
        const Rule::VectorStrings &assets,
        const Rule::MapStrings &active_metrics,
        const Rule::SetStrings &inactive_metrics,
        std::function<Rule::VectorStrings (const Rule::VectorStrings &)> evaluate) {
    Rule::VectorVectorStrings result;
    for (const std::string &asset : assets) {
        Rule::VectorStrings metric_values;
        bool valid = true;
        for (const std::string &metric : metrics) {
            std::string metric_key = metric + "@" + asset;
            if (inactive_metrics.find (metric_key) != inactive_metrics.end ()) {
                // metric is unavailable, from stream input
                // TODO: FIXME: this should be used if we decide to merge unavailability detection to alert engine
                valid = false;
                break;
            }
            auto metric_value_it = active_metrics.find (metric_key);
            if (metric_value_it == active_metrics.end ()) {
                // metric was not found, it's unavailable, missing in SHM
                // TODO: FIXME: this should be used if we decide to merge unavailability detection to alert engine
                valid = false;
                break;
            }
            metric_values.push_back (metric_value_it->second);
        }
        if (valid) {
            result.push_back (evaluate (metric_values));
            result.back ().push_back (asset);
        }
    }
    return result;
}

/// helper to save lua evaluator to json
void saveLuaToSerializedObject (cxxtools::SerializationInfo &si, const std::string root_name,
        const std::string &code, const int &outcome_items) {
    cxxtools::SerializationInfo *root = si.findMember (root_name);
    if (root != nullptr) {
        root->addMember ("evaluation") <<= code;
        root->addMember ("outcome_item_count") <<= outcome_items;
    }
}
/// helper to load lua evaluator from json
void loadLuaFromSerializedObject (const cxxtools::SerializationInfo &si, std::string &code, int &outcome_items) {
    const cxxtools::SerializationInfo &root = si.getMember (0);
    const cxxtools::SerializationInfo *evaluation = root.findMember ("evaluation");
    if (evaluation != nullptr) {
        *evaluation >>= code;
    }
    const cxxtools::SerializationInfo *outcome_item_count = root.findMember ("outcome_item_count");
    if (outcome_item_count != nullptr) {
        *outcome_item_count >>= outcome_items;
    }
}

void SingleRule::loadFromSerializedObject (const cxxtools::SerializationInfo &si) {
    int outcome_items = -1;
    std::string code = std::string ();
    loadLuaFromSerializedObject (si, code, outcome_items);
    if (outcome_items != -1)
        setOutcomeItems (outcome_items);
    if (!code.empty ()) {
        DecoratorLuaEvaluate::setGlobalVariables (variables_);
        setCode (code);
    } else {
        setCode ("");
    }
}

void SingleRule::saveToSerializedObject (cxxtools::SerializationInfo &si) const {
    Rule::saveToSerializedObject (si);
    saveLuaToSerializedObject (si, whoami (), getCode (), getOutcomeItems ());
}

SingleRule::SingleRule (const std::string name, const Rule::VectorStrings metrics, const Rule::VectorStrings assets,
        const Rule::VectorStrings categories, const ResultsMap results, const std::string code,
        const DecoratorLuaEvaluate::VariableMap variables) :
        Rule (name, metrics, assets, categories, results), DecoratorLuaEvaluate () {
    if (assets_.size () != 1)
        throw invalid_argument_count ("assets");
    if (code.empty ())
        throw missing_mandatory_item ("evaluation");
    Rule::setGlobalVariables (variables);
    DecoratorLuaEvaluate::setGlobalVariables (variables);
    setCode (code);
}

SingleRule::SingleRule (const std::string json) : Rule (json), DecoratorLuaEvaluate () {
    std::istringstream iss (json);
    cxxtools::JsonDeserializer jd (iss);
    jd.deserialize (*this); // runs operator >>= on this object
    if (assets_.size () != 1)
        throw invalid_argument_count ("assets");
    if (getCode ().empty ())
        throw missing_mandatory_item ("evaluation");
}

Rule::VectorStrings SingleRule::evaluate (const Rule::VectorStrings &metrics) {
    return DecoratorLuaEvaluate::evaluate (metrics);
}

Rule::VectorVectorStrings SingleRule::evaluate (const Rule::MapStrings &active_metrics,
        const Rule::SetStrings &inactive_metrics) {
    return evaluate_helper (metrics_, assets_, active_metrics, inactive_metrics,
        std::bind (
            static_cast<Rule::VectorStrings (SingleRule::*)(const Rule::VectorStrings &)>(&SingleRule::evaluate),
            this, std::placeholders::_1)
        );
}

/// deserialization of rule
void operator>>= (const cxxtools::SerializationInfo& si, SingleRule &rule) {
    rule.loadFromSerializedObject (si);
}

void PatternRule::loadFromSerializedObject (const cxxtools::SerializationInfo &si) {
    int outcome_items = -1;
    std::string code = std::string ();
    loadLuaFromSerializedObject (si, code, outcome_items);
    if (outcome_items != -1)
        setOutcomeItems (outcome_items);
    if (!code.empty ()) {
        DecoratorLuaEvaluate::setGlobalVariables (variables_);
        setCode (code);
    } else {
        setCode ("");
    }
}

void PatternRule::saveToSerializedObject (cxxtools::SerializationInfo &si) const {
    Rule::saveToSerializedObject (si);
    saveLuaToSerializedObject (si, whoami (), getCode (), getOutcomeItems ());
}

PatternRule::PatternRule (const std::string name, const Rule::VectorStrings metrics, const Rule::VectorStrings assets,
        const Rule::VectorStrings categories, const ResultsMap results, const std::string code,
        const DecoratorLuaEvaluate::VariableMap variables) :
        Rule (name, metrics, assets, categories, results), DecoratorLuaEvaluate () {
    if (metrics_.size () != 1)
        throw invalid_argument_count ("metrics");
    if (code.empty ())
        throw missing_mandatory_item ("evaluation");
    metric_regex_ = std::regex (metrics_[0]);
    Rule::setGlobalVariables (variables);
    DecoratorLuaEvaluate::setGlobalVariables (variables);
    setCode (code);
}

PatternRule::PatternRule (const std::string json) : Rule (json), DecoratorLuaEvaluate () {
    if (metrics_.size () != 1)
        throw invalid_argument_count ("metrics");
    std::istringstream iss (json);
    cxxtools::JsonDeserializer jd (iss);
    jd.deserialize (*this); // runs operator >>= on this object
    metric_regex_ = std::regex (metrics_[0]);
    if (getCode ().empty ())
        throw missing_mandatory_item ("evaluation");
}

Rule::VectorStrings PatternRule::evaluate (const Rule::VectorStrings &metrics) {
    if (metrics.size () == 1) {
        Rule::VectorStrings metrics_copy (metrics);
        metrics_copy.insert (metrics_copy.begin (), metrics_[0]);
        return DecoratorLuaEvaluate::evaluate (metrics_copy);
    } else if (metrics.size () == 2) {
        // name of pattern expected as first argument
        return DecoratorLuaEvaluate::evaluate (metrics);
    } else {
        throw invalid_argument_count ("metrics");
    }
}

Rule::VectorVectorStrings PatternRule::evaluate (const Rule::MapStrings &active_metrics,
        const Rule::SetStrings &inactive_metrics) {
    Rule::VectorVectorStrings result;
    Rule::VectorStrings metric_values;
    // unavailable metrics are not considered, as there are no outages on alert produced
    for (const auto active_metric_it : active_metrics) {
        if (std::regex_match (active_metric_it.first, metric_regex_)) {
            metric_values.push_back (active_metric_it.first);
            metric_values.push_back (active_metric_it.second);
            result.push_back (evaluate (metric_values));
            auto at_pos = active_metric_it.first.find ('@');
            if (at_pos != std::string::npos) {
                result.back ().push_back (active_metric_it.first.substr (at_pos + 1));
            } else {
                result.back ().push_back (active_metric_it.first);
            }
            metric_values.clear ();
        }
    }
    return result;
}

/// deserialization of rule
void operator>>= (const cxxtools::SerializationInfo& si, PatternRule &rule) {
    rule.loadFromSerializedObject (si);
}

void ThresholdRule::loadFromSerializedObject (const cxxtools::SerializationInfo &si) {
    int outcome_items = -1;
    std::string code = std::string ();
    loadLuaFromSerializedObject (si, code, outcome_items);
    if (outcome_items != -1)
        setOutcomeItems (outcome_items);
    if (!code.empty ()) {
        DecoratorLuaEvaluate::setGlobalVariables (variables_);
        setCode (code);
    } else {
        setCode ("");
    }
}

void ThresholdRule::saveToSerializedObject (cxxtools::SerializationInfo &si) const {
    Rule::saveToSerializedObject (si);
    saveLuaToSerializedObject (si, whoami (), getCode (), getOutcomeItems ());
}

ThresholdRule::ThresholdRule (const std::string name, const Rule::VectorStrings metrics,
        const Rule::VectorStrings assets, const Rule::VectorStrings categories,
        const ResultsMap results, const std::string code, const DecoratorLuaEvaluate::VariableMap variables) :
        Rule (name, metrics, assets, categories, results), DecoratorLuaEvaluate () {
    Rule::setGlobalVariables (variables);
    if (!code.empty ()) {
        DecoratorLuaEvaluate::setGlobalVariables (variables);
        setCode (code);
    }
    if (code.empty ())
        throw missing_mandatory_item ("evaluation");
}

ThresholdRule::ThresholdRule (const std::string json) : Rule (json), DecoratorLuaEvaluate () {
    std::istringstream iss (json);
    cxxtools::JsonDeserializer jd (iss);
    jd.deserialize (*this); // runs operator >>= on this object
    if (variables_.size () == 0)
        throw invalid_argument_count ("values");
    for (auto &var_it : variables_) {
        if (var_it.first != "low_critical" && var_it.first != "low_warning" && var_it.first != "high_critical" &&
                var_it.first != "high_warning")
            throw wrong_argument ("values");
    }
    if (getCode ().empty ())
        throw missing_mandatory_item ("evaluation");
}

Rule::VectorStrings ThresholdRule::evaluate (const Rule::VectorStrings &metrics) {
    return DecoratorLuaEvaluate::evaluate (metrics);
}

Rule::VectorVectorStrings ThresholdRule::evaluate (const Rule::MapStrings &active_metrics,
        const Rule::SetStrings &inactive_metrics) {
    return evaluate_helper (metrics_, assets_, active_metrics, inactive_metrics,
        std::bind (
            static_cast<Rule::VectorStrings (ThresholdRule::*)(const Rule::VectorStrings &)>(&ThresholdRule::evaluate),
            this, std::placeholders::_1)
        );
}

/// deserialization of rule
void operator>>= (const cxxtools::SerializationInfo& si, ThresholdRule &rule) {
    rule.loadFromSerializedObject (si);
}

FlexibleRule::FlexibleRule (const std::string name, const Rule::VectorStrings metrics, const Rule::VectorStrings assets,
        const Rule::VectorStrings categories, const ResultsMap results, const std::string code,
        const DecoratorLuaEvaluate::VariableMap variables) :
        Rule (name, metrics, assets, categories, results), DecoratorLuaEvaluate () {
    Rule::setGlobalVariables (variables);
    if (!code.empty ()) {
        DecoratorLuaEvaluate::setGlobalVariables (variables);
        setCode (code);
    }
    if (code.empty ())
        throw missing_mandatory_item ("evaluation");
}

FlexibleRule::FlexibleRule (const std::string json) : Rule (json), DecoratorLuaEvaluate () {
    std::istringstream iss (json);
    cxxtools::JsonDeserializer jd (iss);
    jd.deserialize (*this); // runs operator >>= on this object
    if (getCode ().empty ())
        throw missing_mandatory_item ("evaluation");
}

void FlexibleRule::loadFromSerializedObject (const cxxtools::SerializationInfo &si) {
    const cxxtools::SerializationInfo &elem_content = si.getMember (0);
    loadOptionalArray (elem_content, "models", models_);
    int outcome_items = -1;
    std::string code = std::string ();
    loadLuaFromSerializedObject (si, code, outcome_items);
    if (outcome_items != -1)
        setOutcomeItems (outcome_items);
    if (!code.empty ()) {
        DecoratorLuaEvaluate::setGlobalVariables (variables_);
        setCode (code);
    } else {
        setCode ("");
    }
}

void FlexibleRule::saveToSerializedObject (cxxtools::SerializationInfo &si) const {
    Rule::saveToSerializedObject (si);
    cxxtools::SerializationInfo *elem_content = si.findMember (whoami ());
    if (elem_content != nullptr) {
        elem_content->addMember ("models") <<= models_;
    }
    saveLuaToSerializedObject (si, whoami (), getCode (), getOutcomeItems ());
}

Rule::VectorStrings FlexibleRule::evaluate (const Rule::VectorStrings &metrics) {
    return DecoratorLuaEvaluate::evaluate (metrics);
}

Rule::VectorVectorStrings FlexibleRule::evaluate (const Rule::MapStrings &active_metrics,
        const Rule::SetStrings &inactive_metrics) {
    return evaluate_helper (metrics_, assets_, active_metrics, inactive_metrics,
        std::bind (
            static_cast<Rule::VectorStrings (FlexibleRule::*)(const Rule::VectorStrings &)>(&FlexibleRule::evaluate),
            this, std::placeholders::_1)
        );
}

/// deserialization of rule
void operator>>= (const cxxtools::SerializationInfo& si, FlexibleRule &rule) {
    rule.loadFromSerializedObject (si);
}

//  --------------------------------------------------------------------------
//  Self test of this class

// If your selftest reads SCMed fixture data, please keep it in
// src/selftest-ro; if your test creates filesystem objects, please
// do so under src/selftest-rw.
// The following pattern is suggested for C selftest code:
//    char *filename = NULL;
//    filename = zsys_sprintf ("%s/%s", SELFTEST_DIR_RO, "mytemplate.file");
//    assert (filename);
//    ... use the "filename" for I/O ...
//    zstr_free (&filename);
// This way the same "filename" variable can be reused for many subtests.
#define SELFTEST_DIR_RO "src/selftest-ro"
#define SELFTEST_DIR_RW "src/selftest-rw"

void
extended_rules_test (bool verbose)
{
    printf (" * extended_rules: ");

    // create single rule with lua
    SingleRule sr1 ("single1@asset4",
        {"single1.metric1"},
        {"asset4"},
        {"CAT_ALL"},
        {   {"ok", {{}, "OK", "ok_description"}},
            {"fail", {{}, "CRITICAL", "fail_description"}}},
        "function main (i1) if tonumber (i1) < tonumber (var1) then return 'ok' else return 'fail' end end",
        {{"var1", "50"}});
    SingleRule sr1j (sr1.getJsonRule ());
    assert (sr1 == sr1j);
    Rule::VectorStrings sr1_eval1_results = sr1.evaluate ({"40"});
    Rule::VectorStrings sr1_eval1_expected = {"ok"};
    assert (sr1_eval1_results == sr1_eval1_expected);
    Rule::VectorVectorStrings sr1_eval2_results = sr1.evaluate ({{"single1.metric1@asset4", "40"}},
        Rule::SetStrings ());
    Rule::VectorVectorStrings sr1_eval2_expected = {{"ok", "asset4"}};
    assert (sr1_eval2_results == sr1_eval2_expected);

    // create pattern rule with lua
    PatternRule pr1 ("pattern1@asset5",
        {"pattern..metric1@.*"},
        {"asset5"},
        {"CAT_ALL"},
        {   {"ok", {{}, "OK", "ok_description"}},
            {"fail", {{}, "CRITICAL", "fail_description"}}},
        std::string ("function main (metric, i1) if tonumber (i1) < tonumber (var1) then return 'ok', metric ") +
        "else return 'fail', metric end end",
        {{"var1", "50"}});
    pr1.setOutcomeItems (2);
    PatternRule pr1j (pr1.getJsonRule ());
    assert (pr1 == pr1j);
    Rule::VectorStrings pr1_eval1_results = pr1.evaluate ({"40"});
    Rule::VectorStrings pr1_eval1_expected = {"ok", "pattern..metric1@.*"};
    assert (pr1_eval1_results == pr1_eval1_expected);
    pr1_eval1_results = pr1.evaluate ({"pattern1.metric1@asset5", "40"});
    pr1_eval1_expected = {"ok", "pattern1.metric1@asset5"};
    assert (pr1_eval1_results == pr1_eval1_expected);
    Rule::VectorVectorStrings pr1_eval2_results = pr1.evaluate ({{"pattern1.metric1@asset5", "40"}},
        Rule::SetStrings ());
    Rule::VectorVectorStrings pr1_eval2_expected = {{"ok", "pattern1.metric1@asset5", "asset5"}};
    assert (pr1_eval2_results == pr1_eval2_expected);
    pr1_eval2_results = pr1.evaluate ({
            {"pattern1.metric1@asset5", "40"},
            {"pattern2.metric1@asset6", "60"},
            {"pattern30.metric1@asset7", "40"},
            {"pattern4.metric1@", "40"},
            {"patern5.metric1@asset8", "40"}}, Rule::SetStrings ());
    pr1_eval2_expected = {{"ok", "pattern1.metric1@asset5", "asset5"},
            {"fail", "pattern2.metric1@asset6", "asset6"},
            {"ok", "pattern4.metric1@", ""}};
    assert (pr1_eval2_results == pr1_eval2_expected);

    // create threshold rule for single metric without lua
    ThresholdRule tr1 ("threshold1@asset1",
        {"threshold1.metric1"},
        {"asset1"},
        {"CAT_ALL"},
        {   {"ok", {{}, "OK", "ok_description"}},
            {"low_critical", {{}, "CRITICAL", "low_critical_description"}},
            {"low_warning", {{}, "WARNING", "low_warning_description"}},
            {"high_critical", {{}, "CRITICAL", "high_critical_description"}},
            {"high_warning", {{}, "WARNING", "high_warning_description"}}},
        "function main (i1) if tonumber (i1) < tonumber (high_critical) then return 'ok' else return 'fail' end end",
        {{"low_critical", "10"}, {"low_warning", "20"}, {"high_critical", "90"}, {"high_warning", "80"}});
    ThresholdRule tr1j (tr1.getJsonRule ());
    assert (tr1 == tr1j);
    Rule::VectorStrings tr1_eval1_results = tr1.evaluate ({"40"});
    Rule::VectorStrings tr1_eval1_expected = {"ok"};
    assert (tr1_eval1_results == tr1_eval1_expected);
    Rule::VectorVectorStrings tr1_eval2_results = tr1.evaluate ({{"threshold1.metric1@asset1", "40"}},
        Rule::SetStrings ());
    Rule::VectorVectorStrings tr1_eval2_expected = {{"ok", "asset1"}};
    assert (tr1_eval2_results == tr1_eval2_expected);

    // create threshold rule for multiple metrics with lua
log_debug ("HERE: %d", __LINE__);
    ThresholdRule tr2 ("threshold2@asset2",
        {"threshold2.metric1", "threshold2.metric2"},
        {"asset2"},
        {"CAT_ALL"},
        {   {"ok", {{}, "OK", "ok_description"}},
            {"fail", {{}, "CRITICAL", "fail_description"}}},
        "function main (i1, i2) if tonumber (i1) < tonumber (low_warning) and tonumber (i2) < tonumber (high_warning) "
                "then return 'ok' else return 'fail' end end",
        {{"low_warning", "10"}, {"high_warning", "20"}});
    ThresholdRule tr2j (tr2.getJsonRule ());
    assert (tr2 == tr2j);
    Rule::VectorStrings tr2_eval1_results = tr2.evaluate ({"5", "15"});
    Rule::VectorStrings tr2_eval1_expected = {"ok"};
    assert (tr2_eval1_results == tr2_eval1_expected);
    Rule::VectorVectorStrings tr2_eval2_results = tr2.evaluate ({{"threshold2.metric1@asset2", "5"},
            {"threshold2.metric2@asset2", "15"}}, Rule::SetStrings ());
    Rule::VectorVectorStrings tr2_eval2_expected = {{"ok", "asset2"}};
    assert (tr2_eval2_results == tr2_eval2_expected);

    // create flexible rule with lua
log_debug ("HERE: %d", __LINE__);
    FlexibleRule fr1 ("flexible1@asset3",
        {"flexible1.metric1"},
        {"asset3"},
        {"CAT_ALL"},
        {   {"ok", {{}, "OK", "ok_description"}},
            {"fail", {{}, "CRITICAL", "fail_description"}}},
        "function main (i1) if i1 == 'good' then return 'ok' else return 'fail' end end",
        {});
    FlexibleRule fr1j (fr1.getJsonRule ());
    assert (fr1 == fr1j);
    Rule::VectorStrings fr1_eval1_results = fr1.evaluate ({"good"});
    Rule::VectorStrings fr1_eval1_expected = {"ok"};
    assert (fr1_eval1_results == fr1_eval1_expected);
    Rule::VectorVectorStrings fr1_eval2_results = fr1.evaluate ({{"flexible1.metric1@asset3", "good"}},
        Rule::SetStrings ());
    Rule::VectorVectorStrings fr1_eval2_expected = {{"ok", "asset3"}};
    assert (fr1_eval2_results == fr1_eval2_expected);

    printf ("OK\n");
}
