/*  =========================================================================
    fty_alert_engine_audit_log - Manage audit log

    Copyright (C) 2014 - 2021 Eaton

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

#include "fty_alert_engine_audit_log.h"
#include <stdio.h>

Ftylog* AuditLogManager::_auditLogger = nullptr;

//  init audit logger
void AuditLogManager::init(const std::string& serviceName, const std::string& confFileName)
{
    if (!_auditLogger) {
        const char* loggerName = "audit/alarms";

        _auditLogger = ftylog_new(loggerName, confFileName.c_str());
        if (!_auditLogger) {
            log_error("Audit logger initialization failed (%s, %s)", loggerName, confFileName.c_str());
        }
        else {
            log_info("Audit logger initialization (%s, %s)", loggerName, confFileName.c_str());
            log_info_alarms_engine_audit("Audit logger initialization (%s)", serviceName.c_str());
        }
    }
}

//  deinit audit logger
void AuditLogManager::deinit()
{
    if (_auditLogger) {
        ftylog_delete(_auditLogger);
        _auditLogger = nullptr;
    }
}

//  return audit logger instance
Ftylog* AuditLogManager::getInstance()
{
    return _auditLogger;
}
