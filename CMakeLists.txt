cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

project(fty-alert-engine
    VERSION 1.0.0
    DESCRIPTION "42ity service evaluating rules written in Lua and producing alerts"
)

##############################################################################################################
find_package(fty-cmake PATHS ${CMAKE_BINARY_DIR}/fty-cmake)
##############################################################################################################


##############################################################################################################
etn_target(static ${PROJECT_NAME}-static
    SOURCES
        src/alertconfiguration.cc
        src/autoconfig.cc
        src/fty_alert_actions.cc
        src/fty_alert_engine_audit_log.cc
        src/luarule.cc
        src/metriclist.cc
        src/purealert.cc
        src/rule.cc
        src/ruleconfigurator.cc
        src/templateruleconfigurator.cc
        src/thresholdrulecomplex.cc
        src/utils.cc
    INCLUDE_DIRS
       include
    USES
        czmq
        cxxtools  # cxxtools cannot be use as public because we do not have the cmake package yet
        fty_common
        fty_common_logging
        fty_proto
        mlm
        fty_shm
        lua5.1
    PRIVATE
)
##############################################################################################################
etn_target(exe ${PROJECT_NAME}-server
    SOURCES
        src/fty_alert_engine.cc
        src/fty_alert_engine_server.cc
    INCLUDE_DIRS
        include
    USES
        ${PROJECT_NAME}-static
        czmq
        cxxtools  # cxxtools cannot be use as public because we do not have the cmake package yet
        fty_common
        fty_common_logging
        fty_proto
        mlm
        fty_shm
        lua5.1
)

#install systemd config

etn_configure_file(
    src/${PROJECT_NAME}.service.in

    TARGET      ${PROJECT_NAME}-server
    DESTINATION /usr/lib/systemd/system/
)

#install config file

etn_configure_file( 
    src/conf/fty-alert-engine.cfg.in    
    TARGET ${PROJECT_NAME}-server
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/fty-alert-engine/"
)

install(
    FILES ${PROJECT_SOURCE_DIR}/src/conf/fty-alert-engine-log.cfg
    DESTINATION ${CMAKE_INSTALL_FULL_SYSCONFDIR}/fty/fty-alert-engine
)

install(
    FILES ${PROJECT_SOURCE_DIR}/src/warranty.rule
    DESTINATION ${CMAKE_INSTALL_PREFIX}/var/lib/fty/fty-alert-engine
)

install(
    FILES ${PROJECT_SOURCE_DIR}/src/warranty.rule
    DESTINATION ${CMAKE_INSTALL_PREFIX}/var/lib/fty/fty-alert-engine
)

##############################################################################################################

if(BUILD_TESTING)
    enable_testing()

    # Create a target for the tests
    etn_test(${PROJECT_NAME}-test
        SOURCES
            src/fty_alert_engine_server.cc
            test/fty_alert_engine_private_selftest.cc
            test/fty_alert_engine_selftest.cc
        INCLUDE_DIRS
            include
            src
        USES
            ${PROJECT_NAME}-static
            czmq
            cxxtools  # cxxtools cannot be use as public because we do not have the cmake package yet
            fty_common
            fty_common_logging
            fty_proto
            mlm
            fty_shm
            lua5.1
    )
    
endif()

##############################################################################################################
