/*  =========================================================================
    audit_log - Manage audit log

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

#include <fty_log.h>

class AuditLog
{
private:
    AuditLog()  = default;
    ~AuditLog() = default;
    static Ftylog* _auditLogger;

public:
    // Return singleton Audit Ftylog instance
    static Ftylog* getInstance();
    static void    init(const std::string& serviceName, const std::string& confFileName = FTY_COMMON_LOGGING_DEFAULT_CFG);
    static void    deinit();
};

// audit log macros (printf va format)
#define audit_log_info(...) log_info_log(AuditLog::getInstance(), __VA_ARGS__);
#define audit_log_error(...) log_error_log(AuditLog::getInstance(), __VA_ARGS__);
