/*  =========================================================================
    alert - Alert representation
    Copyright (C) 2014 - 2018 Eaton
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
    alert - Alert representation
@discuss
@end
*/

#include "fty_alert_engine_classes.h"

std::string
s_replace_tokens (
        std::string desc,
        std::string severity,
        std::string name,
        std::string ename,
        std::string logical_asset,
        std::string logical_asset_ename,
        std::string normal_state,
        std::string port)
{
    std::string rule_result = severity;
    std::transform (rule_result.begin (), rule_result.end (), rule_result.begin (), ::tolower);

    // this list came from templateruleconfigurator
    std::vector<std::string> patterns = {"__severity__", "__name__", "__ename__", "__logicalasset_iname__", "__logicalasset__", "__normalstate__", "__port__", "__rule_result__"};
    std::vector<std::string> replacements = {severity, name, ename, logical_asset, logical_asset_ename, normal_state, port, rule_result};

    std::string result = desc;
    int i = 0;
    for (auto &p : patterns)
    {
        size_t pos = 0;
        while ((pos = result.find (p, pos)) != std::string::npos){
            result.replace (pos, p.length (), replacements.at (i));
            pos += replacements.at (i).length ();
        }
        ++i;
    }

    return result;
}

void
Alert::update (fty_proto_t *msg)
{
    if (fty_proto_id (msg) != FTY_PROTO_ALERT) {
        std::string msg ("Wrong fty-proto type");
        throw std::runtime_error (msg);
    }
    int outcome_count = fty_proto_aux_number (msg, "outcome_count", 0);
    std::string outcome = fty_proto_aux_string (msg, "outcome", "ok");
    if (outcome_count <= 0) {
        m_Outcome.clear ();
        m_Outcome.push_back (outcome);
    } else {
        m_Outcome.clear ();
        for (int i = 0; i < outcome_count; ++i) {
            std::string outcome_x_key = std::string ("outcome.") + std::to_string (i);
            std::string outcome_x = fty_proto_aux_string (msg, outcome_x_key.c_str (), "");
            m_Outcome.push_back (outcome_x);
        }
    }
    if (m_Ctime == 0) {
        m_Ctime = fty_proto_time (msg);
        m_Mtime = fty_proto_time (msg);
    }
    if (m_Name.empty ())
        m_Name = fty_proto_name (msg);
    if (m_Rule.empty ())
        m_Rule = fty_proto_rule (msg);
    m_Ttl = fty_proto_ttl (msg);
    m_Severity = m_Results[outcome].severity_;
    m_Description = m_Results[outcome].description_;
    m_Actions = m_Results[outcome].actions_;
}

void
Alert::overwrite (fty_proto_t *msg)
{
    if (msg == nullptr)
        return;
    if (fty_proto_id (msg) != FTY_PROTO_ALERT) {
        std::string msg ("Wrong fty-proto type");
        throw std::runtime_error (msg);
    }
    if (!isAckState (m_State)) {
        const char *state = nullptr;
        state = fty_proto_state (msg);
        if (state != nullptr)
            m_State = StringToAlertState (state);
    }
    m_Ctime = fty_proto_time (msg);
    m_Mtime = fty_proto_time (msg);
}

void
Alert::overwrite (GenericRule rule)
{
    //m_Id = rule.getName ();
    m_Results = rule.getResults ();
    m_State = RESOLVED;
    m_Outcome.clear ();
    m_Outcome.push_back ("ok");
    m_Ctime = 0;
    m_Mtime = 0;
    m_Ttl = std::numeric_limits<uint64_t>::max ();
    m_Severity.clear ();
    m_Description.clear ();
    m_Actions.clear ();
}

void
Alert::cleanup ()
{
    uint64_t now = zclock_mono ()/1000;
    m_State = RESOLVED;
    m_Outcome.clear ();
    m_Outcome.push_back ("ok");
    m_Ctime = now;
    m_Mtime = now;
    m_Severity.clear ();
    m_Description.clear ();
    m_Actions.clear ();
}

int
Alert::switchState (std::string state_str) {
    if (state_str == "RESOLVED") {
        // allow this transition always
        m_State = RESOLVED;
    }
    else if (state_str == "ACK-IGNORE") {
        if (m_State == RESOLVED)
            return -1;
        else
            m_State = ACKIGNORE;
    }
    else if (state_str == "ACK-PAUSE") {
        if (m_State == RESOLVED)
            return -1;
        else
            m_State = ACKPAUSE;
    }
    else if (state_str == "ACK-SILENCE") {
        if (m_State == RESOLVED)
            return -1;
        else
            m_State = ACKSILENCE;
    }
    else if (state_str == "ACK-WIP") {
        if (m_State == RESOLVED)
            return -1;
        else
            m_State = ACKWIP;
    }
    else if (state_str == "ACTIVE") {
        if (isAckState (m_State))
            return -1;
        else
            m_State = ACTIVE;
    }
    return 0;
}

zmsg_t *
Alert::toFtyProto (
        std::string ename,
        std::string logical_asset,
        std::string logical_asset_ename,
        std::string normal_state,
        std::string port)
{
    zhash_t *aux = zhash_new ();
    zhash_autofree (aux);
    zhash_insert (aux, "ctime", (void *) std::to_string (m_Ctime).c_str ());

    zlist_t *actions = zlist_new ();
    zlist_autofree (actions);
    for (auto action : m_Actions) {
        zlist_append (actions, (void *) action.c_str ());
    }

    //int sep = m_Id.find ('@');
    //std::string rule = m_Id.substr (0, sep);
    //std::string name = m_Id.substr (sep+1);

    std::string description = s_replace_tokens (
            m_Description,
            m_Severity,
            m_Name,
            ename,
            logical_asset,
            logical_asset_ename,
            normal_state,
            port);

    zmsg_t *tmp = fty_proto_encode_alert (
            aux,
            m_Mtime,
            m_Ttl,
            m_Rule.c_str (),
            m_Name.c_str (),
            AlertStateToString (m_State).c_str (),
            m_Severity.c_str (),
            description.c_str (),
            actions
            );

    zlist_destroy (&actions);
    zhash_destroy (&aux);
    return tmp;
}

zmsg_t *
Alert::StaleToFtyProto ()
{
    zhash_t *aux = zhash_new ();
    zlist_t *actions = zlist_new ();

    //int sep = m_Id.find ('@');
    //std::string rule = m_Id.substr (0, sep);
    //std::string name = m_Id.substr (sep+1);

    zmsg_t *tmp = fty_proto_encode_alert (
            aux,
            m_Mtime,
            m_Ttl,
            m_Rule.c_str (),
            m_Name.c_str (),
            AlertStateToString (m_State).c_str (),
            "",
            "",
            actions
            );

    zlist_destroy (&actions);
    zhash_destroy (&aux);
    return tmp;
}

zmsg_t *
Alert::TriggeredToFtyProto ()
{
    zhash_t *aux = zhash_new ();
    zhash_autofree (aux);
    zhash_insert (aux, "outcome", (void *) m_Outcome[0].c_str ());
    if (m_Outcome.size () > 1) {
        zhash_insert (aux, "outcome_count", (void *) std::to_string (m_Outcome.size ()).c_str ());
        for (size_t i = 0; i < m_Outcome.size (); ++i) {
            std::string outcome_x_key = std::string ("outcome.") + std::to_string (i);
            zhash_insert (aux, outcome_x_key.c_str (), (void *) std::to_string (m_Outcome.size ()).c_str ());
        }
    }

    zlist_t *actions = zlist_new ();

    zmsg_t *tmp = fty_proto_encode_alert (
            aux,
            m_Mtime,
            m_Ttl,
            m_Rule.c_str (),
            m_Name.c_str (),
            AlertStateToString (m_State).c_str (),
            "",
            "",
            actions
            );

    zlist_destroy (&actions);
    zhash_destroy (&aux);
    return tmp;
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
alert_test (bool verbose)
{
    //  @selftest
    printf (" * alert: ");
    std::string rule = "average.temperature@datacenter-3";
    std::string name = "datacenter-3";

    // put in proper results
    std::vector<std::string> actions = {"EMAIL", "SMS"};
    Rule::Outcome high_critical;
    high_critical.severity_ = "CRITICAL";
    high_critical.description_ = "Average temperature in __ename__ is critically high";
    high_critical.actions_ = actions;

    Rule::Outcome high_warning;
    high_warning.severity_ = "WARNING";
    high_warning.description_ = "Average temperature in __ename__ is high";
    high_warning.actions_ = actions;

    Rule::Outcome low_warning;
    low_warning.severity_ = "WARNING";
    low_warning.description_ = "Average temperature in __ename__ is low";
    low_warning.actions_ = actions;

    Rule::Outcome low_critical;
    low_critical.severity_ = "CRITICAL";
    low_critical.description_ = "Average temperature in __ename__ is critically low";
    low_critical.actions_ = actions;

    Rule::ResultsMap tmp;
    tmp.insert (std::pair<std::string, Rule::Outcome> ("high_critical", high_critical));
    tmp.insert (std::pair<std::string, Rule::Outcome> ("high_warning", high_warning));
    tmp.insert (std::pair<std::string, Rule::Outcome> ("low_warning", low_warning));
    tmp.insert (std::pair<std::string, Rule::Outcome> ("low_critical", low_critical));

    uint64_t now = zclock_time () / 1000;
    // create fty-proto msg
    {
        Alert alert (rule, name, "RESOLVED");
        alert.setResults (tmp);
        assert (alert.outcome () == "ok");
        assert (alert.ctime () == 0);
        assert (alert.mtime () == 0);
        assert (alert.ttl () == std::numeric_limits<uint64_t>::max ());
        assert (alert.state () == "RESOLVED");
        assert (alert.description ().empty ());
        assert (alert.actions ().empty ());

        zhash_t *aux = zhash_new ();
        zhash_autofree (aux);
        zhash_insert (aux, "outcome", (void *) "high_warning");
        zlist_t *fty_actions = zlist_new ();

        uint64_t mtime = now;
        uint64_t ttl = 5;

        zmsg_t *msg = fty_proto_encode_alert (
                aux,
                mtime,
                ttl,
                rule.c_str (),
                name.c_str (),
                "ACTIVE",
                "",
                "",
                fty_actions
                );
        // do update and overwrite
        fty_proto_t *fty_msg = fty_proto_decode (&msg);

        alert.update (fty_msg);
        assert (alert.outcome () == "high_warning");
        assert (alert.ctime () == now);
        assert (alert.ttl () == ttl);
        log_error ("%s", alert.severity ().c_str ());
        assert (alert.severity () == "WARNING");
        assert (alert.description () == "Average temperature in __ename__ is high");
        assert (alert.actions ()[0] == "EMAIL");
        assert (alert.actions ()[1] == "SMS");

        alert.overwrite (fty_msg);
        assert (alert.ctime () == now);
        assert (alert.mtime () == now);
        assert (alert.state () == "ACTIVE");

        // switch state
        alert.switchState ("ACK-SILENCE");
        assert (alert.state () == "ACK-SILENCE");
        fty_proto_destroy (&fty_msg);
        zlist_destroy (&fty_actions);
        zhash_destroy (&aux);

        // convert acked, warning alert to fty-proto
        zmsg_t *alert_msg =  alert.toFtyProto ("DC-Roztoky", "", "", "", "");
        fty_proto_t *fty_alert_msg = fty_proto_decode (&alert_msg);
        assert (fty_proto_aux_number (fty_alert_msg, "ctime", 0) == now);
        assert (fty_proto_time (fty_alert_msg) == now);
        log_error ("%s", fty_proto_rule (fty_alert_msg));
        assert (streq (fty_proto_rule (fty_alert_msg), rule.c_str ()));
        assert (streq (fty_proto_name (fty_alert_msg), name.c_str ()));
        assert (fty_proto_ttl (fty_alert_msg) == ttl);
        assert (streq (fty_proto_severity (fty_alert_msg), "WARNING"));
        assert (streq (fty_proto_state (fty_alert_msg), "ACK-SILENCE"));
        assert (streq (fty_proto_description (fty_alert_msg), "Average temperature in DC-Roztoky is high"));
        zlist_t *fty_alert_msg_actions = fty_proto_action (fty_alert_msg);
        assert (streq ((const char *) zlist_first (fty_alert_msg_actions), actions[0].c_str ()));
        assert (streq ((const char *) zlist_next (fty_alert_msg_actions), actions[1].c_str ()));
        fty_proto_destroy (&fty_alert_msg);

        // cleanup the first alert
        alert.cleanup ();
        assert (alert.state () == "RESOLVED");
        assert (alert.outcome () == "ok");
        assert (alert.severity () == "");
        assert (alert.description () == "");
        assert (alert.actions ().empty ());
        // convert timed out alert to fty-proto
        zmsg_t *alert_stale_msg = alert.StaleToFtyProto ();
        fty_proto_t *fty_alert_stale_msg = fty_proto_decode (&alert_stale_msg);
        assert (fty_alert_stale_msg);
        assert (streq (fty_proto_rule (fty_alert_stale_msg), rule.c_str ()));
        assert (streq (fty_proto_name (fty_alert_stale_msg), name.c_str ()));
        assert (fty_proto_ttl (fty_alert_stale_msg) == ttl);
        assert (streq (fty_proto_severity (fty_alert_stale_msg), ""));
        assert (streq (fty_proto_state (fty_alert_stale_msg), "RESOLVED"));
        assert (streq (fty_proto_description (fty_alert_stale_msg), ""));
        zlist_t *alert_stale_msg_actions = fty_proto_action (fty_alert_stale_msg);
        assert ((const char *) zlist_first (alert_stale_msg_actions) ==  NULL);
        fty_proto_destroy (&fty_alert_stale_msg);
    }

    {
        // create alert2 - triggered
        Alert alert2 (rule, name, "ACTIVE");
        std::vector<std::string> outcomes = {"high_critical"};
        alert2.setOutcomes (outcomes);

        //zhash_t *aux = zhash_new ();
        //zhash_autofree (aux);
        //zhash_insert (aux, "outcome", (void *) "high_critical");
        //zlist_t *fty_actions = zlist_new ();

        //uint64_t mtime = now;
        //uint64_t ttl = 5;

        //zmsg_t *msg = fty_proto_encode_alert (
        //        aux,
        //        mtime,
        //        ttl,
        //        rule.c_str (),
        //        name.c_str (),
        //        "ACTIVE",
        //        "",
        //        "",
        //        fty_actions
        //        );
        //fty_proto_t *fty_msg = fty_proto_decode (&msg);
        //alert2.update (fty_msg);
        //fty_proto_destroy (&fty_msg);
        //zlist_destroy (&fty_actions);
        //zhash_destroy (&aux);

        // convert basic alert (triggered by rule evaluation) to fty-proto
        zmsg_t *alert2_msg = alert2.TriggeredToFtyProto ();
        fty_proto_t *fty_alert2_msg = fty_proto_decode (&alert2_msg);
        assert (streq (fty_proto_aux_string (fty_alert2_msg, "outcome", ""), "high_critical"));
        assert (streq (fty_proto_rule (fty_alert2_msg), rule.c_str ()));

        assert (streq (fty_proto_name (fty_alert2_msg), name.c_str ()));
        fty_proto_destroy (&fty_alert2_msg);
    }

    {
        // create alert3, overwrite it with a Rule
        Alert alert3 (rule + "@" + name, tmp);
        std::string rule_json ("{\"test\":{\"name\":\"metric@asset1\",\"categories\":[\"CAT_ALL\"],\"metrics\":[\"");
        rule_json += "metric1\"],\"results\":[{\"ok\":{\"action\":[],\"severity\":\"CRITICAL\",\"description\":\"";
        rule_json += "ok_description\",\"threshold_name\":\"\"}}],\"assets\":[\"asset1\"],\"values\":[{\"var1\":\"val1\"},{\"";
        rule_json += "var2\":\"val2\"}]}}";
        GenericRule generic_rule (rule_json);
        alert3.overwrite (generic_rule);
        assert (alert3.outcome () == "ok");
        assert (alert3.ctime () == 0);
        assert (alert3.mtime () == 0);
        assert (alert3.ttl () == std::numeric_limits<uint64_t>::max ());
        assert (alert3.state () == "RESOLVED");
        assert (alert3.description ().empty ());
        assert (alert3.actions ().empty ());

        // update it from fty-proto
        zhash_t *aux = zhash_new ();
        zhash_autofree (aux);
        zhash_insert (aux, "outcome", (void *) "ok");
        zlist_t *fty_actions = zlist_new ();

        uint64_t mtime = now;
        uint64_t ttl = 5;

        zmsg_t *msg = fty_proto_encode_alert (
                aux,
                mtime,
                ttl,
                rule.c_str (),
                name.c_str (),
                "ACTIVE",
                "",
                "",
                fty_actions
                );
        fty_proto_t *fty_msg = fty_proto_decode (&msg);
        alert3.update (fty_msg);
        assert (alert3.outcome () == "ok");
        assert (alert3.ctime () == now);
        assert (alert3.ttl () == ttl);
        assert (alert3.severity () == "CRITICAL");
        assert (alert3.description () == "ok_description");
        assert (alert3.actions ().empty ());
        fty_proto_destroy (&fty_msg);
        zlist_destroy (&fty_actions);
        zhash_destroy (&aux);

        // convert alert resolved by rule change to fty-proto
        zmsg_t *alert_msg =  alert3.toFtyProto ("DC-Roztoky", "", "", "", "");
        fty_proto_t *fty_alert_msg = fty_proto_decode (&alert_msg);
        assert (fty_proto_aux_number (fty_alert_msg, "ctime", 0) == now);
        assert (fty_proto_time (fty_alert_msg) == now);
        assert (streq (fty_proto_rule (fty_alert_msg), "average.temperature@datacenter-3"));
        assert (streq (fty_proto_name (fty_alert_msg), "datacenter-3"));
        assert (fty_proto_ttl (fty_alert_msg) == ttl);
        assert (streq (fty_proto_severity (fty_alert_msg), "CRITICAL"));
        assert (streq (fty_proto_state (fty_alert_msg), "RESOLVED"));
        assert (streq (fty_proto_description (fty_alert_msg), "ok_description"));
        zlist_t *fty_alert_msg_actions = fty_proto_action (fty_alert_msg);
        assert ((const char *) zlist_first (fty_alert_msg_actions) ==  NULL);
        fty_proto_destroy (&fty_alert_msg);
    }
    //  @end
    printf ("OK\n");
}
