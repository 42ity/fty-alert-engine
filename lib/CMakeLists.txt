cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

etn_target(static ${PROJECT_NAME}-static
    PRIVATE
    SOURCES
        src/misc/*
        src/rule/*
        src/metric/*
        src/*
    PUBLIC_INCLUDE_DIR
        src
    USES
        czmq
        mlm
        cxxtools
        lua5.4
        fty_common
        fty_common_logging
        fty_proto
        fty_shm
        fty-utils
        stdc++fs
)

etn_test_target(${PROJECT_NAME}-static
    CONFIGS
        test/templates/*
        test/testrules/*
        test/audit/*
    SOURCES
        test/main.cpp
        test/utils.cpp
        test/json.cpp
        test/outcome.cpp
        test/audit.cpp
        test/autoconfig.cpp
        test/templateruleconfigurator.cpp
        test/alertconfiguration.cpp
        test/engine_server.cpp
        test/alert_actions.cpp
    SUBDIR
        test
)
