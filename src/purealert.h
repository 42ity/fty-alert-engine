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

/*! \file purealert.h
 *  \author Alena Chernikava <AlenaChernikava@Eaton.com>
 *  \brief General representation of alert
 */
#ifndef SRC_PUREALERT_H
#define SRC_PUREALERT_H

#include <string>
#include <vector>

#define ALERT_UNKNOWN  0
#define ALERT_START    1
#define ALERT_ACK1     2
#define ALERT_ACK2     3
#define ALERT_ACK3     4
#define ALERT_ACK4     5
#define ALERT_RESOLVED 6

const char* get_status_string(int status)
{
    switch (status) {
        case ALERT_START:
            return "ACTIVE";
        case ALERT_ACK1:
            return "ACK-WIP";
        case ALERT_ACK2:
            return "ACK-PAUSE";
        case ALERT_ACK3:
            return "ACK-IGNORE";
        case ALERT_ACK4:
            return "ACK-SILENCE";
        case ALERT_RESOLVED:
            return "RESOLVED";
    }
    return "UNKNOWN";
}


struct PureAlert{
    int status; // on Off ack
    int64_t timestamp;
    std::string description;
    std::string element;
    std::string severity;
    std::vector <std::string> actions;

    PureAlert(int s, int64_t tm, const std::string &descr, const std::string &element_name)
    {
        status = s;
        timestamp = tm;
        description = descr;
        element = element_name;
    };

    PureAlert()
    {
    };
};

void printPureAlert(const PureAlert &pureAlert){
//    zsys_info ("status = %d", pureAlert.status);
//    zsys_info ("timestamp = %d", pureAlert.timestamp);
//    zsys_info ("description = %s", pureAlert.description.c_str());
//    zsys_info ("element = %s", pureAlert.element.c_str());
}

#endif // SRC_PURE_ALERT_H_
