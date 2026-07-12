cmake_minimum_required(VERSION 3.13)
cmake_policy(VERSION 3.13)

project(fty-alert-engine
    VERSION 1.0.0
    DESCRIPTION "fty-alert-engine"
)

find_package(fty-cmake PATHS ${CMAKE_BINARY_DIR}/fty-cmake)

##############################################################################################################

add_subdirectory(lib)
add_subdirectory(agent)

##############################################################################################################

set(AGENT_USER "bios")
set(RULE_TEMPLATES_SHARE_DIR "${CMAKE_INSTALL_FULL_DATAROOTDIR}/bios/fty-autoconfig")
set(AGENT_CONF_DIR "${CMAKE_INSTALL_FULL_SYSCONFDIR}/${PROJECT_NAME}")
set(AGENT_CONF_FILE "${AGENT_CONF_DIR}/fty-alert-engine.cfg")

set(res ${PROJECT_SOURCE_DIR}/resources)

# install service -> lib/systemd/system/
etn_configure_file(
    ${res}/fty-alert-engine.service.in
    TARGET ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/systemd/system/
)

# install service conf -> lib/tmpfiles.d/
etn_configure_file(
    ${res}/fty-alert-engine.conf.in
    TARGET ${PROJECT_NAME}
    DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/tmpfiles.d/
)

# install cfg file -> etc/
etn_configure_file(
    ${res}/fty-alert-engine.cfg.in
    TARGET ${PROJECT_NAME}
    DESTINATION ${AGENT_CONF_DIR}/
)

# install rule files -> usr/share/bios/fty-autoconfig
FILE(GLOB rule_templates "${PROJECT_SOURCE_DIR}/lib/rule_templates/*.rule")
foreach(file ${rule_templates})
    install(FILES ${file} DESTINATION ${RULE_TEMPLATES_SHARE_DIR}/)
endforeach()

# warranty.rule exception
install(FILES ${PROJECT_SOURCE_DIR}/lib/warranty.rule
    DESTINATION ${CMAKE_INSTALL_LOCALSTATEDIR}/lib/fty/${PROJECT_NAME}
)
