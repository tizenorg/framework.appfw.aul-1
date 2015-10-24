
cmake_minimum_required(VERSION 2.6)
#set(CMAKE_SKIP_BUILD_RPATH true)
set(CMAKE_ALLOW_LOOSE_LOOP_CONSTRUCTS true)

### Get required CFLAGS, LDFLAGS from pkg-config
include(FindPkgConfig)
pkg_check_modules(delegator_pkgs REQUIRED dbus-1 glib-2.0 dbus-glib-1 gio-2.0 gio-unix-2.0 dlog vasum security-server)

foreach(flag ${delegator_pkgs_CFLAGS})
    set(delegator_pkgs_CFLAGS_str "${delegator_pkgs_CFLAGS_str} ${flag}")
endforeach()

### Set current binary dir to be included (for generated *.h files)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR})

#GDBUS specific code
add_custom_command(OUTPUT delegator_client_gdbus_generated.c delegator_client_gdbus_generated.h
            COMMAND gdbus-codegen --generate-c-code delegator_client_gdbus_generated
            --interface-prefix delegator ${CMAKE_CURRENT_SOURCE_DIR}/delegator.xml
            )

### Build modules
add_executable(aul-delegator-server
            delegator_client_gdbus_generated.c
            delegator_server.c
            )
set_target_properties(aul-delegator-server PROPERTIES COMPILE_FLAGS "${delegator_pkgs_CFLAGS_str} -fPIE")
target_link_libraries(aul-delegator-server bundle aul ${delegator_pkgs_LDFLAGS} "-pie")
add_dependencies(aul-delegator-server delegator_client_gdbus_generated.h)
add_dependencies(aul-delegator-server delegator_client_gdbus_generated.c)

add_library(aul-delegator-client STATIC
            delegator_client_gdbus_generated.c
            delegator_client.c
            )
set_target_properties(aul-delegator-client PROPERTIES COMPILE_FLAGS "${delegator_pkgs_CFLAGS_str} ${CFLAGS} -fPIC")
target_link_libraries(aul-delegator-client bundle ${delegator_pkgs_LDFLAGS})
add_dependencies(aul-delegator-client delegator_client_gdbus_generated.h)
add_dependencies(aul-delegator-client delegator_client_gdbus_generated.c)

### Create pc file
configure_file(org.tizen.aul.delegator.service.in org.tizen.aul.delegator.service @ONLY)

## Install
INSTALL(TARGETS aul-delegator-client DESTINATION lib COMPONENT RuntimeLibraries)
INSTALL(TARGETS aul-delegator-server DESTINATION bin)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/org.tizen.aul.delegator.service DESTINATION ${PREFIX}/share/dbus-1/system-services/)
INSTALL(FILES ${CMAKE_CURRENT_BINARY_DIR}/aul-delegator-server.service DESTINATION ${PREFIX}/lib/systemd/system/)



