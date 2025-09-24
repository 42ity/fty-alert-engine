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

#include "purealert.h"

#include <fty_log.h>
#include <sstream>

//static
bool PureAlert::isStatusKnown(const std::string& status)
{
    return (status == ALERT_RESOLVED)
           || (status == ALERT_START)
           || (status == ALERT_ACK1)
           || (status == ALERT_ACK2)
           || (status == ALERT_ACK3)
           || (status == ALERT_ACK4)
    ;
}

std::string PureAlert::str() const
{
    std::ostringstream oss;
    oss << "status(" << _status << ")"
        << ", timestamp(" << _timestamp << ")"
        << ", description(" << _description << ")"
        << ", element(" << _element << ")"
        << ", severity(" << _severity << ")"
        << ", rule_class(" << _rule_class << ")"
        << ", ttl(" << _ttl << ")";

    return oss.str();
}

void PureAlert::print() const
{
    logDebug("{}", str());
}
