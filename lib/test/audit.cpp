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

#include <catch2/catch.hpp>

#include "src/misc/audit_log.h"
#include <fty_log.h>

#include <sys/stat.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <filesystem>

TEST_CASE("audit")
{
    const bool verbose = false;
    std::cout << "Running audit test..." << std::endl;

    {
        using std::filesystem::current_path;
        char tmp[256];
        getcwd(tmp, sizeof(tmp));
        std::cout << "Current working directory: " << tmp << std::endl;
    }

    ManageFtyLog::setInstanceFtylog ("fty-alert-engine-audit-test");
    if (verbose) {
        ManageFtyLog::getInstanceFtylog()->setVerboseMode();
    }

    std::string LOG_CONFIG_FILE = "./test/audit/fty-alert-engine-log-test.cfg";
    std::string LOG_OUTPUT_FILE = "/tmp/alarms-audit-test.log";

    // load log config file (MaxFileSize=1MB, MaxBackupIndex=3)
    std::cout << "Loading " << LOG_CONFIG_FILE << std::endl;
    ManageFtyLog::getInstanceFtylog()->setConfigFile(LOG_CONFIG_FILE);

    // initialize log for auditability
    std::cout << "Audit initialization from " << LOG_CONFIG_FILE << std::endl;
    AuditLog::init("alert-engine-test-audit-log", LOG_CONFIG_FILE);

    std::cout << "Check audit instance" << std::endl;
    CHECK(AuditLog::getInstance() != nullptr);

    // fulfill logs
    std::cout << "Fulfill logs" << std::endl;
    const int NB_LOG = 100000;
    for (int i=0; i < NB_LOG; i++) {
        audit_log_info("AUDIT LOG TEST %0.5d", i);
    }

    // check if file log is created
    std::cout << "Check logs access" << std::endl;
    CHECK(access(LOG_OUTPUT_FILE.c_str(), F_OK) != -1);

    // check if file log size is superior to 0
    std::cout << "Check logs size" << std::endl;
    {
        std::ifstream file(LOG_OUTPUT_FILE, std::ifstream::in | std::ifstream::binary);
        file.seekg(0, std::ios::end);
        auto fileSize = file.tellg();
        CHECK(fileSize > 0);
    }

    // for each archive rollfile (NB=3)
    for (char c= '1'; c <= '3'; c++) {
        // check if archive file is created
        std::string log_file = LOG_OUTPUT_FILE + "." + c;
        std::cout << "Check logs file: " << log_file << std::endl;

        // check if archive file is created
        CHECK(access(log_file.c_str(), F_OK) != -1);

        // check if archive file size is superior to 1Mo
        std::ifstream file(log_file.c_str(), std::ifstream::in | std::ifstream::binary);
        file.seekg(0, std::ios::end);
        auto fileSize = file.tellg();
        CHECK(fileSize > 1*1024*1024);

        //delete the archive file test
        remove(log_file.c_str());
    }

    // delete the log file test
    remove(LOG_OUTPUT_FILE.c_str());

    // release audit context
    AuditLog::deinit();

    std::cout << "audit test done" << std::endl;
}

