#pragma once

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <string>
#include <vector>

namespace snmp
{

using namespace std::string_view_literals;

using version_t = decltype(SNMP_VERSION_2c);
constexpr version_t version2c = SNMP_VERSION_2c;
constexpr version_t version3 = SNMP_VERSION_3;

using level_t = decltype(SNMP_SEC_LEVEL_NOAUTH);
constexpr level_t noAuthNoPriv = SNMP_SEC_LEVEL_NOAUTH;
constexpr level_t authNoPriv = SNMP_SEC_LEVEL_AUTHNOPRIV;
constexpr level_t authPriv = SNMP_SEC_LEVEL_AUTHPRIV;

struct Config
{
    std::string appName;
    std::string peername;
    version_t version;
    std::string communityString;
    std::string username;
    std::string engineID;
    level_t securityLevel;
    std::string authProtocol;
    std::string authKey;
    std::string privProtocol;
    std::string privKey;
};

class Agent
{
  public:
    explicit Agent(Config&& config);
    ~Agent();

    void setVersion(version_t version);
    void setCommunityString(std::string_view community);
    void setUsername(std::string_view name);
    void setPeername(std::string_view peername);
    void setEngineID(std::string_view engineID);
    void setSecurityLevel(level_t securityLevel);
    void setAuthProtocol(std::string_view protocol);
    void setAuthKey(std::string_view key);
    void setPrivProtocol(std::string_view protocol);
    void setPrivKey(std::string_view key);

    void sendTrap(std::string&& message);

  private:
    void initLibrary();
    void closeLibrary();

    void initSession();

    void createTrapSession();
    void closeTrapSession();

    void createTrapPDU();
    void setSysUpTime();
    void setTrapOID();
    void setTrapMessage(std::string&& message);
    void sendPDU();

  private:
    std::vector<unsigned char>
        getBytesFromEngineIDString(std::string_view engineID) const;

  private:
    Config config_;
    snmp_session sessionConfig_;
    snmp_session* trapSession_ = nullptr;
    snmp_pdu* trapPDU_ = nullptr;
};

} // namespace snmp