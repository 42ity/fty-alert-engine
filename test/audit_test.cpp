#include <catch2/catch.hpp>
#include <fty_log.h>
#include "src/fty_alert_engine_audit_log.h"

#include <sys/stat.h>
#include <unistd.h>
#include <iostream>
#include <fstream>
#include <filesystem>

TEST_CASE("audit-test")
{
    const bool verbose = false;
    std::cout << "-- udit-test --" << std::endl;

    {
        using std::filesystem::current_path;
        char tmp[256];
        getcwd(tmp, 256);
        std::cout << "Current working directory: " << tmp << std::endl;
    }

    ManageFtyLog::setInstanceFtylog ("fty-alert-engine-audit-test");
    if (verbose)
        ManageFtyLog::getInstanceFtylog()->setVeboseMode();

    std::string LOG_CONFIG_FILE = "./test/audit/fty-alert-engine-log-test.cfg";

    // load log config file (MaxFileSize=1MB, MaxBackupIndex=3)
    std::cout << "Loading " << LOG_CONFIG_FILE << std::endl;
    ManageFtyLog::getInstanceFtylog()->setConfigFile(LOG_CONFIG_FILE);

    // initialize log for auditability
    std::cout << "Audit init. " << LOG_CONFIG_FILE << std::endl;
    AlertsEngineAuditLogManager::init(LOG_CONFIG_FILE.c_str());

    // fulfill logs
    std::cout << "Fulfill logs" << std::endl;
    const int NB_LOG = 100000;
    for (int i=0; i < NB_LOG; i++) {
      log_info_alarms_engine_audit("AUDIT LOG TEST %0.5d", i);
    }

    std::string LOG_OUTPUT_FILE = "/tmp/alarms-audit-test.log";

    // check if file log  is created
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

    // for each archive file (NB=3)
    for (char c= '1'; c <= '3'; c++) {
        // check if archive file is created
        std::string log_file = LOG_OUTPUT_FILE + "." + c;
        std::cout << "Check logs file:" << log_file << std::endl;

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
    AlertsEngineAuditLogManager::deinit();

    printf(" * Check log config file test : OK\n");
}

