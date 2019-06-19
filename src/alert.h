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

#ifndef ALERT_H_INCLUDED
#define ALERT_H_INCLUDED

#include <limits>
#include <fty_proto.h>

#include "rule.h"

#ifdef __cplusplus
extern "C" {
#endif

///  Self test of this class
FTY_ALERT_ENGINE_PRIVATE void
    alert_test (bool verbose);
//  @end

#ifdef __cplusplus
}
#endif

//  @interface
class Alert {
    public:
        explicit Alert (std::string id, Rule::ResultsMap results):
            m_Id (id),
            m_Results (results),
            m_State (RESOLVED),
            m_Outcome ({"OK"}),
            m_Ctime (0),
            m_Mtime (0),
            m_Ttl (std::numeric_limits<uint64_t>::max ())
        {}

        std::string id () { return m_Id; }
        void setResults (Rule::ResultsMap results)
            { m_Results = results; }
        std::string state () { return AlertStateToString (m_State); }
        void setState (std::string state) { m_State = StringToAlertState (state); }
        uint64_t ctime () { return m_Ctime; }
        void setCtime (uint64_t ctime) { m_Ctime = ctime; }
        uint64_t mtime () { return m_Mtime; }
        void setMtime (uint64_t mtime) { m_Mtime = mtime; }
        uint64_t ttl () { return m_Ttl; }
        void setTtl (uint64_t ttl) { m_Ttl = ttl; }
        std::string outcome () { return m_Outcome[0]; }
        void setOutcome (std::string outcome) { m_Outcome.clear (); m_Outcome.push_back (outcome); }
        std::vector<std::string> outcomes () { return m_Outcome; }
        void setOutcomes (std::vector<std::string> outcomes) { m_Outcome = outcomes; }
        std::string severity () { return m_Severity; }
        std::string description () { return m_Description; }
        std::vector<std::string> actions () { return m_Actions; }

        void overwrite (fty_proto_t *msg);
        void overwrite (std::shared_ptr<Rule> rule);
        void update (fty_proto_t *msg);
        void cleanup ();
        int switchState (std::string state_str);
        zmsg_t *
        toFtyProto (
                std::string ename,
                std::string logical_asset,
                std::string logical_asset_ename,
                std::string normal_state,
                std::string port);
        zmsg_t *StaleToFtyProto ();
        zmsg_t *TriggeredToFtyProto ();
        friend void alert_test (bool verbose);
    private:
        enum AlertState : uint8_t
        {
            RESOLVED = 0,
            ACTIVE,
            ACKIGNORE,
            ACKPAUSE,
            ACKSILENCE,
            ACKWIP
        };

        std::string AlertStateToString (AlertState state)
        {
            std::string tmp;
            switch (state) {
                case RESOLVED: tmp = "RESOLVED"; break;
                case ACTIVE: tmp = "ACTIVE"; break;
                case ACKIGNORE: tmp = "ACK-IGNORE"; break;
                case ACKPAUSE: tmp = "ACK-PAUSE"; break;
                case ACKSILENCE: tmp = "ACK-SILENCE"; break;
                case ACKWIP: tmp = "ACK-WIP"; break;
                default: break; // return empty string
            }

            return tmp;
        }

        AlertState StringToAlertState (std::string state_str)
        {
            AlertState state = RESOLVED;
            if (state_str == "RESOLVED")
                state = RESOLVED;
            else if (state_str == "ACTIVE")
                state = ACTIVE;
            else if (state_str == "ACK-IGNORE")
                state = ACKIGNORE;
            else if (state_str == "ACK-PAUSE")
                state = ACKPAUSE;
            else if (state_str == "ACK-SILENCE")
                state = ACKSILENCE;
            else if (state_str == "ACK-WIP")
                state = ACKWIP;

            return state;
        }

        bool isAckState (AlertState state)
        {
            return (state == ACKIGNORE || state == ACKPAUSE || state == ACKSILENCE || state == ACKWIP);
        }

        std::string m_Id;
        Rule::ResultsMap m_Results;
        AlertState m_State;
        std::vector<std::string> m_Outcome;
        uint64_t m_Ctime;
        uint64_t m_Mtime;
        uint64_t m_Ttl;
        std::string m_Severity;
        std::string m_Description;
        std::vector<std::string> m_Actions;
};
//  @end

#endif
