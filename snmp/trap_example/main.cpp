#include "snmp.h"

#include <exception>
#include <iostream>

int main()
{
    using namespace std::string_literals;
    using namespace std::string_view_literals;
    try
    {
        constexpr auto appName = "snmpapp"sv;
        snmp::Agent agent(appName);

        constexpr auto peername = "172.40.1.4:162"sv;
        agent.setPeername(peername);
        // v2c
        {
            agent.setVersion(snmp::version2c);

            constexpr auto communityString = "public"sv;
            agent.setCommunityString(communityString);

            const std::string message =
                "Test message for version: "s + std::string(snmp::version2c);
            agent.sendTrap(std::move(message));
        }

        // v3
        {
            agent.setVersion(snmp::snmpV3);
            {
                // noAuthNoPriv
                constexpr auto username = "user1"sv;
                agent.setUsername(username);

                constexpr auto engineID = "01 02 03 04 05"sv;
                agent.setEngineID(engineID);

                constexpr auto level = SNMP_SEC_LEVEL_NOAUTH;
                agent.setSecurityLevel(level);

                const std::string message = "Test message for version: "s +
                                            std::string(snmp::snmpV3) +
                                            " noAuthNoPriv"s;
                agent.sendTrap(std::move(message));
            }

            {
                //  authNoPriv
                constexpr auto username = "user2"sv;
                agent.setUsername(username);

                constexpr auto engineID = "02 03 04 05 06"sv;
                agent.setEngineID(engineID);

                constexpr auto level = SNMP_SEC_LEVEL_AUTHNOPRIV;
                agent.setSecurityLevel(level);

                constexpr auto authProtocol = "SHA"sv;
                agent.setAuthProtocol(authProtocol);

                constexpr auto authKey = "authPass123"sv;
                agent.setAuthKey(authKey);

                const std::string message = "Test message for version: "s +
                                            std::string(snmp::snmpV3) +
                                            " authNoPriv"s;
                agent.sendTrap(std::move(message));
            }

            {
                //  authPriv
                constexpr auto username = "user3"sv;
                agent.setUsername(username);

                constexpr auto engineID = "03 04 05 06 07"sv;
                agent.setEngineID(engineID);

                constexpr auto level = SNMP_SEC_LEVEL_AUTHPRIV;
                agent.setSecurityLevel(level);

                constexpr auto authProtocol = "SHA"sv;
                agent.setAuthProtocol(authProtocol);

                constexpr auto authKey = "authPass123"sv;
                agent.setAuthKey(authKey);

                constexpr auto privProtocol = "AES"sv;
                agent.setPrivProtocol(privProtocol);

                constexpr auto privKey = "privPass123"sv;
                agent.setPrivKey(privKey);

                const std::string message = "Test message for version: "s +
                                            std::string(snmp::snmpV3) +
                                            " authPriv"s;
                agent.sendTrap(std::move(message));
            }
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << '\n';
    }
}