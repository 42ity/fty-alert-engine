cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

project(fty-alert-engine
    VERSION 1.0.0
    DESCRIPTION "42ity service evaluating rules written in Lua and producing alerts"
    LANGUAGES CXX
)

##############################################################################################################
find_package(fty-cmake PATHS ${CMAKE_BINARY_DIR}/fty-cmake)
##############################################################################################################


##############################################################################################################
etn_target(static ${PROJECT_NAME}-static
    SOURCES
        src/alertconfiguration.cc
        src/alertconfiguration.h
        src/autoconfig.cc
        src/autoconfig.h
        src/fty_alert_actions.cc
        src/fty_alert_actions.h
        src/fty_alert_engine_audit_log.cc
        src/fty_alert_engine_audit_log.h
        src/fty_alert_engine_server.cc
        src/fty_alert_engine_server.h
        src/luarule.cc
        src/luarule.h
        src/metricinfo.h
        src/metriclist.cc
        src/metriclist.h
        src/normalrule.h
        src/purealert.cc
        src/purealert.h
        src/regexrule.h
        src/rule.cc
        src/ruleconfigurator.cc
        src/ruleconfigurator.h
        src/rule.h
        src/templateruleconfigurator.cc
        src/templateruleconfigurator.h
        src/thresholdrulecomplex.cc
        src/thresholdrulecomplex.h
        src/thresholdruledevice.h
        src/thresholdrulesimple.h
        src/utils.cc
        src/utils.h
    USES
        czmq
        cxxtools
        fty_common
        fty_common_logging
        fty_proto
        mlm
        fty_shm
        fty-utils
        lua5.1
        stdc++fs
    PRIVATE
)

##############################################################################################################

etn_target(exe ${PROJECT_NAME}
    SOURCES
        src/fty_alert_engine.cc
        src/fty_alert_engine.h
    USES
        ${PROJECT_NAME}-static
        lua5.1
)

##############################################################################################################

set(AGENT_USER "bios")
set(RULE_TEMPLATES_SHARE_DIR "${CMAKE_INSTALL_FULL_DATAROOTDIR}/bios/fty-autoconfig")

# install systemd config

etn_configure_file(
    src/conf/${PROJECT_NAME}.service.in

    TARGET      ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system/
)

etn_configure_file(
    ${PROJECT_SOURCE_DIR}/src/conf/fty-alert-engine.conf.in
    TARGET      ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/tmpfiles.d/
)

#install config file

etn_configure_file(
    src/conf/fty-alert-engine.cfg.in
    TARGET ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/${PROJECT_NAME}/
)

# rules -> usr/share/bios/fty-autoconfig
FILE(GLOB rule_templates "${PROJECT_SOURCE_DIR}/src/rule_templates/*.rule")
foreach(file ${rule_templates})
  install(FILES ${file} DESTINATION ${RULE_TEMPLATES_SHARE_DIR}/)
endforeach()

# warranty.rule exception
install(
    FILES ${PROJECT_SOURCE_DIR}/src/warranty.rule
    DESTINATION ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/fty/${PROJECT_NAME}
)

##############################################################################################################

etn_test_target(${PROJECT_NAME}-static
    CONFIGS
        test/templates/*
        test/testrules/*
        test/audit/*
    SOURCES
        test/main.cpp
        test/alert_actions.cpp
        test/alertconfiguration.cpp
        test/engine_server_test.cpp
        test/audit_test.cpp
    SUBDIR
        test
)

##############################################################################################################
