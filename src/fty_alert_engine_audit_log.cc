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

/*
@header
    fty_alert_engine_audit_log - Manage alerts audit log
@discuss
@end
*/

#include "fty_alert_engine_audit_log.h"
#include <stdio.h>

Ftylog *AlertsEngineAuditLogManager::_alertsauditlog = nullptr;

//  init audit logger
void AlertsEngineAuditLogManager::init (const char* configLogFile)
{
    if (!_alertsauditlog)
    {
        _alertsauditlog = ftylog_new ("alerts-engine-audit", configLogFile);
    }
}

//  deinit audit logger
void AlertsEngineAuditLogManager::deinit ()
{
    if (_alertsauditlog)
    {
        ftylog_delete(_alertsauditlog);
        _alertsauditlog = nullptr;
    }
}

//  return alerts audit logger
Ftylog* AlertsEngineAuditLogManager::getInstance ()
{
    return _alertsauditlog;
}

// test of the class
void fty_alert_engine_audit_log_test (bool verbose)
{
    const char *SELFTEST_DIR_RO = "src/selftest-ro";
    const char *SELFTEST_DIR_RW = "src/selftest-rw";
    mkdir(SELFTEST_DIR_RW, 0755);
    assert (SELFTEST_DIR_RO);
    assert (SELFTEST_DIR_RW);
    std::string str_SELFTEST_DIR_RO = std::string (SELFTEST_DIR_RO);
    std::string str_SELFTEST_DIR_RW = std::string (SELFTEST_DIR_RW);
    ManageFtyLog::setInstanceFtylog ("fty-alert-engine-audit-test");
    if (verbose)
        ManageFtyLog::getInstanceFtylog()->setVeboseMode();

    // load log config file (MaxFileSize=1MB, MaxBackupIndex=3)
    std::string logConfigFile = str_SELFTEST_DIR_RO + "/fty-alert-engine-log-test.cfg";
    ManageFtyLog::getInstanceFtylog()->setConfigFile(logConfigFile);

    // initialize log for auditability
    AlertsEngineAuditLogManager::init(logConfigFile.c_str());
    const int NB_LOG = 100000;

    for (int i=0; i < NB_LOG; i++) {
      log_info_alarms_engine_audit("AUDIT LOG TEST %0.5d", i);
    }
    // check if file log  is created
    assert(access("./src/selftest-rw/alarms-audit-test.log", F_OK) != -1);
    // check if file log size is superior to 0
    std::ifstream file("./src/selftest-rw/alarms-audit-test.log", std::ifstream::in | std::ifstream::binary);
    file.seekg(0, std::ios::end);
    int fileSize = file.tellg();
    assert(fileSize > 0);
    // for each archive file (NB=3)
    for (char c= '1'; c <= '3'; c++) {
        // check if archive file is created
        std::string log_file = "./src/selftest-rw/alarms-audit-test.log.";
        log_file += c;
        // check if archive file is created
        assert(access(log_file.c_str(), F_OK) != -1);

        // check if archive file size is superior to 1Mo
        std::ifstream file(log_file.c_str(), std::ifstream::in | std::ifstream::binary);
        file.seekg(0, std::ios::end);
        int fileSize = file.tellg();
        assert(fileSize > 1*1024*1024);

        //delete the archive file test
        remove(log_file.c_str());
    }
    //delete the log file test
    remove("./src/selftest-rw/alarms-audit-test.log");

    // release audit context
    AlertsEngineAuditLogManager::deinit();
    printf(" * Check log config file test : OK\n");
}
