#include <catch2/catch.hpp>
#include <fty_log.h>
#include "src/fty_alert_engine_audit_log.h"

#include <sys/stat.h>
#include <unistd.h>
#include <fstream>

TEST_CASE("audit test")
{
    const bool verbose = false;

    ManageFtyLog::setInstanceFtylog ("fty-alert-engine-audit-test");
    if (verbose)
        ManageFtyLog::getInstanceFtylog()->setVeboseMode();

    // load log config file (MaxFileSize=1MB, MaxBackupIndex=3)
    std::string logConfigFile = "./fty-alert-engine-log-test.cfg";
    ManageFtyLog::getInstanceFtylog()->setConfigFile(logConfigFile);

    // initialize log for auditability
    AlertsEngineAuditLogManager::init(logConfigFile.c_str());

    // fulfill logs
    const int NB_LOG = 100000;
    for (int i=0; i < NB_LOG; i++) {
      log_info_alarms_engine_audit("AUDIT LOG TEST %0.5d", i);
    }

    // check if file log  is created
    assert(access("./alarms-audit-test.log", F_OK) != -1);

    // check if file log size is superior to 0
    {
        std::ifstream file("./alarms-audit-test.log", std::ifstream::in | std::ifstream::binary);
        file.seekg(0, std::ios::end);
        auto fileSize = file.tellg();
        CHECK(fileSize > 0);
    }

    // for each archive file (NB=3)
    for (char c= '1'; c <= '3'; c++) {
        // check if archive file is created
        std::string log_file = "./alarms-audit-test.log.";
        log_file += c;

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
    //delete the log file test
    remove("./alarms-audit-test.log");

    // release audit context
    AlertsEngineAuditLogManager::deinit();

    printf(" * Check log config file test : OK\n");
}

