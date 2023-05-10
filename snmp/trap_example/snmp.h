#pragma once

#include <string>

namespace snmp
{
void sendTrap(const std::string& snmpVersion, const bool isAuthenticationKeySet, const bool isEncryptionKeySet);
}