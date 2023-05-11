#include "snmp.h"

#include <exception>
#include <iostream>

int main()
{
    try
    {
        using namespace std::string_literals;
        // v2c
        {
            const std::string snmpVersion = "SNMPv2c"s;
            const bool isAuthenticationKeySet = false;
            const bool isEncryptionKeySet = false;
            snmp::sendTrap(snmpVersion, isAuthenticationKeySet,
                           isEncryptionKeySet);
        }

        // v3
        {
            {
                //  noAuthNoPriv
                const std::string snmpVersion = "SNMPv3"s;
                const bool isAuthenticationKeySet = false;
                const bool isEncryptionKeySet = false;
                snmp::sendTrap(snmpVersion, isAuthenticationKeySet,
                               isEncryptionKeySet);
            }

            {
                //  authNoPriv
                const std::string snmpVersion = "SNMPv3"s;
                const bool isAuthenticationKeySet = true;
                const bool isEncryptionKeySet = false;
                snmp::sendTrap(snmpVersion, isAuthenticationKeySet,
                               isEncryptionKeySet);
            }

            {
                //  authPriv
                const std::string snmpVersion = "SNMPv3"s;
                const bool isAuthenticationKeySet = true;
                const bool isEncryptionKeySet = true;
                snmp::sendTrap(snmpVersion, isAuthenticationKeySet,
                               isEncryptionKeySet);
            }
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << "\n";
    }
}