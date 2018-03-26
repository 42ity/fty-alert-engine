/*
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
*/
#include "fty_alert_engine_classes.h"

bool PureAlert::isStatusKnown (const char *status)
{
    if ( strcmp (status, ALERT_START) == 0 )
        return true;
    if ( strcmp (status, ALERT_ACK1) == 0 )
        return true;
    if ( strcmp (status, ALERT_ACK2) == 0 )
        return true;
    if ( strcmp (status, ALERT_ACK3) == 0 )
        return true;
    if ( strcmp (status, ALERT_ACK4) == 0 )
        return true;
    if ( strcmp (status, ALERT_RESOLVED) == 0 )
        return true;
    return false;
}

void PureAlert::print() const {
    log_debug ("status = %s", _status.c_str());
    log_debug ("timestamp = %" PRIu64, _timestamp);
    log_debug ("description = %s", _description.c_str());
    log_debug ("element = %s", _element.c_str());
    log_debug ("severity = %s", _severity.c_str());
}


