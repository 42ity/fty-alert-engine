/*
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
*/

/// @file purealert.h
/// @author Alena Chernikava <AlenaChernikava@Eaton.com>
/// @brief General representation of alert

#pragma once

#include <memory> //unique_ptr
#include <string>
#include <vector>

// alert status
#define ALERT_START    "ACTIVE"
#define ALERT_ACK1     "ACK-WIP"
#define ALERT_ACK2     "ACK-PAUSE"
#define ALERT_ACK3     "ACK-IGNORE"
#define ALERT_ACK4     "ACK-SILENCE"
#define ALERT_RESOLVED "RESOLVED"
#define ALERT_UNKNOWN  "UNKNOWN"

class PureAlert
{
public:
    std::string              _status{ALERT_UNKNOWN};
    uint64_t                 _timestamp{0};
    std::string              _description;
    std::string              _element;
    std::string              _severity;
    std::vector<std::string> _actions;
    std::string              _rule_class;
    uint64_t                 _ttl{0};

    PureAlert() : _timestamp{0} {}

    PureAlert(
        const std::string& status,
        uint64_t timestamp,
        const std::string& description,
        const std::string& element_name,
        const std::string& rule_class
    ) : _status{status}
      , _timestamp{timestamp}
      , _description{description}
      , _element{element_name}
      , _severity{}
      , _actions{}
      , _rule_class{rule_class}
      , _ttl{0}
    {}

    PureAlert(
        const std::string& status,
        uint64_t timestamp,
        const std::string& description,
        const std::string& element_name,
        const std::string& severity,
        const std::vector<std::string>& actions
    ) : _status{status}
      , _timestamp{timestamp}
      , _description{description}
      , _element{element_name}
      , _severity{severity}
      , _actions{actions}
      , _rule_class{}
      , _ttl{0}
    {}

    static bool isStatusKnown(const std::string& status);

    //dbg
    std::string str() const;
    void print() const;
};

typedef std::unique_ptr<PureAlert> PureAlertPtr;
