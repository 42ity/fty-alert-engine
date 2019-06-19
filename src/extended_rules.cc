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

#include "fty_alert_engine_classes.h"

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
        std::ostringstream oss;
        si.dump (oss);
        log_error ("No evaluation function provided for rule %s", oss.str ().c_str ());
        throw std::runtime_error ("No evaluation function provided for rule " + oss.str ());
    }
}

void SingleRule::saveToSerializedObject (cxxtools::SerializationInfo &si) const {
    Rule::saveToSerializedObject (si);
    saveLuaToSerializedObject (si, whoami (), getCode (), getOutcomeItems ());
}

SingleRule::SingleRule (const std::string name, const Rule::VectorStrings metrics, const Rule::VectorStrings assets,
        const Rule::VectorStrings categories, const ResultsMap results, std::string code,
        DecoratorLuaEvaluate::VariableMap variables) :
        Rule (name, metrics, assets, categories, results) {
    Rule::setGlobalVariables (variables);
    DecoratorLuaEvaluate::setGlobalVariables (variables);
    setCode (code);
}

Rule::VectorStrings SingleRule::evaluate (const Rule::VectorStrings &metrics) {
    return DecoratorLuaEvaluate::evaluate (metrics);
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
        std::ostringstream oss;
        si.dump (oss);
        log_error ("No evaluation function provided for rule %s", oss.str ().c_str ());
        throw std::runtime_error ("No evaluation function provided for rule " + oss.str ());
    }
}

void PatternRule::saveToSerializedObject (cxxtools::SerializationInfo &si) const {
    Rule::saveToSerializedObject (si);
    saveLuaToSerializedObject (si, whoami (), getCode (), getOutcomeItems ());
}

PatternRule::PatternRule (const std::string name, const Rule::VectorStrings metrics, const Rule::VectorStrings assets,
        const Rule::VectorStrings categories, const ResultsMap results, std::string code,
        DecoratorLuaEvaluate::VariableMap variables) :
        Rule (name, metrics, assets, categories, results) {
    Rule::setGlobalVariables (variables);
    DecoratorLuaEvaluate::setGlobalVariables (variables);
    setCode (code);
}

Rule::VectorStrings PatternRule::evaluate (const Rule::VectorStrings &metrics) {
    if (metrics_.size () == 1) {
        Rule::VectorStrings vsmetrics (metrics);
        std::ostringstream pattern_name;
        for (auto it = metrics_.begin (); it != metrics_.end (); it++) {
            if (it != metrics_.begin ()) {
                pattern_name << ", ";
            }
            pattern_name << *it;
        }
        vsmetrics.insert (vsmetrics.begin (), pattern_name.str ());
        return DecoratorLuaEvaluate::evaluate (metrics);
    } else if (metrics.size () == 2) {
        // name of pattern expected as first argument
        return DecoratorLuaEvaluate::evaluate (metrics);
    } else {
        throw std::logic_error ("Invalid metrics count for pattern rule");
    }
}

void ThresholdRule::loadFromSerializedObject (const cxxtools::SerializationInfo &si) {
    if (metrics_.size () != 1) {
        int outcome_items = -1;
        std::string code = std::string ();
        loadLuaFromSerializedObject (si, code, outcome_items);
        if (outcome_items != -1)
            setOutcomeItems (outcome_items);
        if (!code.empty ()) {
            DecoratorLuaEvaluate::setGlobalVariables (variables_);
            setCode (code);
        } else {
            std::ostringstream oss;
            si.dump (oss);
            log_error ("No evaluation function provided for rule %s", oss.str ().c_str ());
            throw std::runtime_error ("No evaluation function provided for rule " + oss.str ());
        }
    }
}

void ThresholdRule::saveToSerializedObject (cxxtools::SerializationInfo &si) const {
    Rule::saveToSerializedObject (si);
    saveLuaToSerializedObject (si, whoami (), getCode (), getOutcomeItems ());
}

ThresholdRule::ThresholdRule (const std::string name, const Rule::VectorStrings metrics,
        const Rule::VectorStrings assets, const Rule::VectorStrings categories,
        const ResultsMap results, std::string code, DecoratorLuaEvaluate::VariableMap variables) :
        Rule (name, metrics, assets, categories, results) {
    Rule::setGlobalVariables (variables);
    if (!code.empty ()) {
        DecoratorLuaEvaluate::setGlobalVariables (variables);
        setCode (code);
    }
}

Rule::VectorStrings ThresholdRule::evaluate (const Rule::VectorStrings &metrics) {
    if (metrics_.size () == 1) {
        // TODO: FIXME: fix this afwul hardcoded list
        if (stod (metrics[0], nullptr) <= stod (variables_["low_critical"], nullptr)) {
            return Rule::VectorStrings { "low_critical" };
        }
        if (stod (metrics[0], nullptr) <= stod (variables_["low_warning"], nullptr)) {
            return Rule::VectorStrings { "low_warning" };
        }
        if (stod (metrics[0], nullptr) >= stod (variables_["high_critical"], nullptr)) {
            return Rule::VectorStrings { "high_critical" };
        }
        if (stod (metrics[0], nullptr) >= stod (variables_["high_warning"], nullptr)) {
            return Rule::VectorStrings { "high_warning" };
        }
        return Rule::VectorStrings { "ok" };
    } else {
        return DecoratorLuaEvaluate::evaluate (metrics);
    }
}

FlexibleRule::FlexibleRule (const std::string name, const Rule::VectorStrings metrics, const Rule::VectorStrings assets,
        const Rule::VectorStrings categories, const ResultsMap results, std::string code,
        DecoratorLuaEvaluate::VariableMap variables) :
        Rule (name, metrics, assets, categories, results) {
    Rule::setGlobalVariables (variables);
    if (!code.empty ()) {
        DecoratorLuaEvaluate::setGlobalVariables (variables);
        setCode (code);
    }
}

FlexibleRule::FlexibleRule (const std::string json) : Rule (json) {
    std::istringstream iss (json);
    cxxtools::JsonDeserializer jd (iss);
    if (jd.si () != nullptr) {
        loadFromSerializedObject (*jd.si ());
    } else {
        throw std::runtime_error ("JSON deserializer has null SerializationInfo for input: " + json);
    }
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
        std::ostringstream oss;
        si.dump (oss);
        log_error ("No evaluation function provided for rule %s", oss.str ().c_str ());
        throw std::runtime_error ("No evaluation function provided for rule " + oss.str ());
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

    // TODO: FIXME: add unit tests here

    printf ("OK\n");
}
