#include "snmp.h"

#include <exception>
#include <iostream>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <signal.h>

#include "bmcHostPowerState.h"

static int keep_running;

RETSIGTYPE stop_server( int a )
{
    keep_running = 0;
}

int main()
{
    using namespace std::string_literals;
    using namespace std::string_view_literals;

    constexpr bool checkV2c = false;
    constexpr bool checkV3NoAuthNoPriv = false;
    constexpr bool checkV3AuthNoPriv = false;
    constexpr bool checkV3AuthPriv = false;
    constexpr bool checkGetRequest = true;

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

        if (checkGetRequest)
        {

            snmp_enable_stderrlog();
            
            // make us a agentx client.
            constexpr bool isAgent = true;
            netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
                                   NETSNMP_DS_AGENT_ROLE, isAgent);

            // initialize tcpip, if necessary
            SOCK_STARTUP;

            const char* agentName = "snmp-get-daemon";
            // initialize the agent library
            init_agent(agentName);

            // initialize mib code here
            init_bmcHostPowerState();

            // example-daemon will be used to read example-daemon.conf files.
            init_snmp(agentName);

            // In case we receive a request to stop (kill -TERM or kill -INT)
            keep_running = 1;
            signal(SIGTERM, stop_server);
            signal(SIGINT, stop_server);

            // your main loop here...
            while (keep_running)
            {
                // if you use select(), see snmp_select_info() in snmp_api(3)
                //     --- OR ---
                agent_check_and_process(1); // 0 == don't block
            }

            // at shutdown time
            snmp_shutdown(agentName);
            SOCK_CLEANUP;
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << '\n';
    }
}