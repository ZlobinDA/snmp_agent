#include "snmp.h"

#include <exception>
#include <iostream>

int main()
{
    using namespace std::string_literals;
    using namespace std::string_view_literals;

    constexpr bool checkV2c = true;
    constexpr bool checkV3NoAuthNoPriv = true;
    constexpr bool checkV3AuthNoPriv = true;
    constexpr bool checkV3AuthPriv = true;

    try
    {
        if (checkV2c)
        {
            snmp::Config config;
            config.appName = "snmpapp"s;
            config.peername = "172.40.1.4:162"s;
            config.version = snmp::version2c;
            config.communityString = "public"s;
            snmp::Agent agent(std::move(config));
            std::string message = "Test message for version 2c"s;
            agent.sendTrap(std::move(message));
        }

        if (checkV3NoAuthNoPriv)
        {
            snmp::Config config;
            config.appName = "snmpapp"s;
            config.peername = "172.40.1.4:162"s;
            config.version = snmp::version3;
            config.username = "user1"s;
            config.engineID = "01 02 03 04 05"s;
            config.securityLevel = snmp::noAuthNoPriv;
            snmp::Agent agent(std::move(config));
            std::string message =
                "Test message for version 3: "s + " noAuthNoPriv"s;
            agent.sendTrap(std::move(message));
        }

        if (checkV3AuthNoPriv)
        {
            snmp::Config config;
            config.appName = "snmpapp"s;
            config.peername = "172.40.1.4:162"s;
            config.version = snmp::version3;
            config.username = "user2"sv;
            config.engineID = "02 03 04 05 06"sv;
            config.securityLevel = snmp::authNoPriv;
            config.authProtocol = "SHA"sv;
            config.authKey = "authPass123"sv;
            snmp::Agent agent(std::move(config));
            std::string message =
                "Test message for version 3: "s + " authNoPriv"s;
            agent.sendTrap(std::move(message));
        }

        if (checkV3AuthPriv)
        {
            snmp::Config config;
            config.appName = "snmpapp"s;
            config.peername = "172.40.1.4:162"s;
            config.version = snmp::version3;
            config.username = "user3"sv;
            config.engineID = "03 04 05 06 07"sv;
            config.securityLevel = snmp::authPriv;
            config.authProtocol = "SHA"sv;
            config.authKey = "authPass123"sv;
            config.privProtocol = "AES"sv;
            config.privKey = "privPass123"sv;
            snmp::Agent agent(std::move(config));
            std::string message =
                "Test message for version 3: "s + " authPriv"s;
            agent.sendTrap(std::move(message));
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << '\n';
    }
}