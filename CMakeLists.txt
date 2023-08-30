cmake_minimum_required(VERSION 3.22)

project(snmp_agent)

add_executable(snmp_agent ./src/main.cpp ./src/snmp.cpp ./src/snmp_exception.cpp ./src/bmcHostPowerState.cpp)

set_target_properties(snmp_agent PROPERTIES
    CXX_STANDART 17
    CXX_STANDART_REQUIRED ON
)

set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -I. `net-snmp-config --cflags`" )

# target_compile_options(send_snmp_trap PRIVATE
#     -Wall -Wextra -pedantic -Werror
# )

find_library(NETSNMP "netsnmp")
find_library(NETSNMPMIBS "netsnmpmibs")
find_library(NETSNMPAGENT "netsnmpagent")

target_link_libraries(snmp_agent ${NETSNMP} ${NETSNMPMIBS} ${NETSNMPAGENT})
