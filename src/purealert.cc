/*
Copyright (C) 2014 - 2015 Eaton

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
#include <czmq.h>
extern int agent_alert_verbose;

#define zsys_debug1(...) \
    do { if (agent_alert_verbose) zsys_debug (__VA_ARGS__); } while (0);

#include "purealert.h"

#include <czmq.h>

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
    zsys_debug1 ("status = %s", _status.c_str());
    zsys_debug1 ("timestamp = %d", _timestamp);
    zsys_debug1 ("description = %s", _description.c_str());
    zsys_debug1 ("element = %s", _element.c_str());
    zsys_debug1 ("severity = %s", _severity.c_str());
}


