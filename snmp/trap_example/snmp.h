#pragma once

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <string>
#include <vector>

namespace snmp
{

using namespace std::string_view_literals;
constexpr std::string_view version2c = "SNMPv2c"sv;
constexpr std::string_view snmpV3 = "SNMPv3"sv;

class Agent
{
public:
    Agent(std::string_view appName);
    ~Agent();

    void setVersion(std::string_view version);
    void setCommunityString(std::string_view community);
    void setUsername(std::string_view name);
    void setPeername(std::string_view peername);
    void setEngineID(std::string_view engineID);
    void setSecurityLevel(int level);
    void setAuthProtocol(std::string_view protocol);
    void setAuthKey(std::string_view key);
    void setPrivProtocol(std::string_view protocol);
    void setPrivKey(std::string_view key);

    void sendTrap(const std::string&& message);

private:
    std::vector<unsigned char> getBytesFromEngineIDString(std::string_view engineID) const;
private:
    const std::string appName_;
    snmp_session session_;
};

}