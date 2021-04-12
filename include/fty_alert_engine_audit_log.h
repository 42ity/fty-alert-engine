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

#pragma once

// #include "fty_alert_engine_library.h"
#include <fty_log.h>

/* Prints message in Audit Log with DEBUG level. */
#define log_debug_alarms_engine_audit(...) log_debug_log(AlertsEngineAuditLogManager::getInstance(), __VA_ARGS__);

/* Prints message in Audit Log with INFO level. */
#define log_info_alarms_engine_audit(...) log_info_log(AlertsEngineAuditLogManager::getInstance(), __VA_ARGS__);

/* Prints message in Audit Log with WARNING level*/
#define log_warning_alarms_engine_audit(...) log_warning_log(AlertsEngineAuditLogManager::getInstance(), __VA_ARGS__);

/* Prints message in Audit Log with ERROR level*/
#define log_error_alarms_engine_audit(...) log_error_log(AlertsEngineAuditLogManager::getInstance(), __VA_ARGS__);

/* Prints message in Audit Log with FATAL level. */
#define log_fatal_alarms_engine_audit(...) log_fatal_log(AlertsEngineAuditLogManager::getInstance(), __VA_ARGS__);

// singleton for logger management
class AlertsEngineAuditLogManager
{
private:
    AlertsEngineAuditLogManager()  = default;
    ~AlertsEngineAuditLogManager() = default;
    static Ftylog* _alertsauditlog;

public:
    // Return singleton Audit Ftylog instance
    static Ftylog* getInstance();
    static void    init(const char* configLogFile);
    static void    deinit();
};
