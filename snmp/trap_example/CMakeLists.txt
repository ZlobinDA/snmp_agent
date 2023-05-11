cmake_minimum_required(VERSION 3.22)

project(snmp_trap_example)

add_executable(send_snmp_trap main.cpp snmp.cpp)

set_target_properties(send_snmp_trap PROPERTIES
    CXX_STANDART 17
    CXX_STANDART_REQUIRED ON
)

# target_compile_options(send_snmp_trap PRIVATE
#     -Wall -Wextra -pedantic -Werror
# )

find_library(NETSNMP "netsnmp")

target_link_libraries(send_snmp_trap ${NETSNMP})
