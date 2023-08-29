#include "snmp.h"

#include "snmp_exception.h"

#include <sstream>
#include <utility>
#include <vector>

namespace snmp
{

Agent::Agent(Config&& config) : config_{config}
{
    initLibrary();
    initSession();
}

Agent::~Agent()
{
    closeLibrary();
}

void Agent::initLibrary()
{
    init_snmp(config_.appName.c_str());
}

void Agent::closeLibrary()
{
    snmp_shutdown(config_.appName.c_str());
}

void Agent::initSession()
{
    snmp_sess_init(&sessionConfig_);
    setPeername(config_.peername);
    setVersion(config_.version);
    if (config_.version == version2c)
    {
        setCommunityString(config_.communityString);
    }
    else if (config_.version == version3)
    {
        setUsername(config_.username);
        setEngineID(config_.engineID);
        setSecurityLevel(config_.securityLevel);
        setAuthProtocol(config_.authProtocol);
        setAuthKey(config_.authKey);
        setPrivProtocol(config_.privProtocol);
        setPrivKey(config_.privKey);
    }
}

void Agent::setPeername(std::string_view peername)
{
    if (peername.empty())
    {
        constexpr auto error = "SNMPv2c: empty peername"sv;
        throw snmp_exception(error);
    }
    sessionConfig_.peername = const_cast<char*>(peername.data());
}

void Agent::setVersion(version_t version)
{
    if (version != version2c && version != version3)
    {
        constexpr auto error = "Invalid SNMP version"sv;
        throw snmp_exception(error);
    }
    sessionConfig_.version = version;
}

void Agent::setCommunityString(std::string_view community)
{
    if (community.empty())
    {
        constexpr auto error = "SNMPv2c: empty community string"sv;
        throw snmp_exception(error);
    }
    sessionConfig_.community =
        reinterpret_cast<u_char*>(const_cast<char*>(community.data()));
    sessionConfig_.community_len = community.size();
}

void Agent::setUsername(std::string_view username)
{
    if (username.empty())
    {
        constexpr auto error = "SNMPv2c: empty username"sv;
        throw snmp_exception(error);
    }
    sessionConfig_.securityName = const_cast<char*>(username.data());
    sessionConfig_.securityNameLen = strlen(sessionConfig_.securityName);
}

void Agent::setEngineID(std::string_view engineID)
{
    if (engineID.empty())
    {
        constexpr auto error = "SNMPv2c: empty engineID"sv;
        throw snmp_exception(error);
    }
    static std::vector<unsigned char> securityEngineID = {0x00, 0x00, 0x00,
                                                          0x00, 0x00};
    securityEngineID = getBytesFromEngineIDString(engineID);
    sessionConfig_.securityEngineID = securityEngineID.data();
    sessionConfig_.securityEngineIDLen = securityEngineID.size();
}

std::vector<unsigned char>
    Agent::getBytesFromEngineIDString(std::string_view engineID) const
{
    std::vector<unsigned char> result;
    std::istringstream id{std::string(engineID)};
    unsigned int byte;
    while (id >> std::hex >> byte)
    {
        result.push_back(byte);
    }
    return result;
}

void Agent::setSecurityLevel(level_t securityLevel)
{
    if (securityLevel != noAuthNoPriv && securityLevel != authNoPriv &&
        securityLevel != authPriv)
    {
        constexpr auto error = "Invalid security level"sv;
        throw snmp_exception(error);
    }
    sessionConfig_.securityLevel = securityLevel;
}

void Agent::setAuthProtocol(std::string_view protocol)
{
    if (config_.securityLevel == noAuthNoPriv)
    {
        return;
    }
    if (config_.securityLevel != noAuthNoPriv && protocol.empty())
    {
        constexpr auto error = "auth protocol is empty"sv;
        throw snmp_exception(error);
    }
    // TODO Add other auth protocols
    sessionConfig_.securityAuthProto = usmHMACSHA1AuthProtocol;
    sessionConfig_.securityAuthProtoLen =
        sizeof(usmHMACSHA1AuthProtocol) / sizeof(oid);
}

void Agent::setAuthKey(std::string_view key)
{
    if (config_.securityLevel == noAuthNoPriv)
    {
        return;
    }
    if (config_.securityLevel != noAuthNoPriv && key.empty())
    {
        constexpr auto error = "auth key is empty"sv;
        throw snmp_exception(error);
    }
    sessionConfig_.securityAuthKeyLen = USM_AUTH_KU_LEN;
    auto securityAuthKey =
        reinterpret_cast<u_char*>(const_cast<char*>(key.data()));
    auto securityAuthKeyLen = key.size();
    if (generate_Ku(sessionConfig_.securityAuthProto,
                    sessionConfig_.securityAuthProtoLen, securityAuthKey,
                    securityAuthKeyLen, sessionConfig_.securityAuthKey,
                    &sessionConfig_.securityAuthKeyLen) != SNMPERR_SUCCESS)
    {
        constexpr auto message =
            "Error generating Ku from authentication pass phrase"sv;
        throw snmp_exception(message);
    }
}

void Agent::setPrivProtocol(std::string_view protocol)
{
    if (config_.securityLevel != authPriv)
    {
        return;
    }
    if (config_.securityLevel == authPriv && protocol.empty())
    {
        constexpr auto error = "priv protocol is empty"sv;
        throw snmp_exception(error);
    }
    // TODO Add other priv protocols
    sessionConfig_.securityPrivProto = usmAESPrivProtocol;
    sessionConfig_.securityPrivProtoLen =
        sizeof(usmAESPrivProtocol) / sizeof(oid);
}

void Agent::setPrivKey(std::string_view key)
{
    if (config_.securityLevel != authPriv)
    {
        return;
    }
    if (config_.securityLevel == authPriv && key.empty())
    {
        constexpr auto error = "priv key is empty"sv;
        throw snmp_exception(error);
    }
    sessionConfig_.securityPrivKeyLen = USM_PRIV_KU_LEN;
    auto securityPrivKey =
        reinterpret_cast<u_char*>(const_cast<char*>(key.data()));
    auto securityPrivKeyLen = key.size();
    if (generate_Ku(sessionConfig_.securityAuthProto,
                    sessionConfig_.securityAuthProtoLen, securityPrivKey,
                    securityPrivKeyLen, sessionConfig_.securityPrivKey,
                    &sessionConfig_.securityPrivKeyLen) != SNMPERR_SUCCESS)
    {
        constexpr auto message =
            "Error generating Ku from encription pass phrase"sv;
        throw snmp_exception(message);
    }
}

void Agent::createTrapSession()
{
    trapSession_ = snmp_add(
        &sessionConfig_,
        netsnmp_transport_open_client("snmptrap", sessionConfig_.peername),
        nullptr, nullptr);
    if (!trapSession_)
    {
        using namespace std::string_literals;
        const std::string message =
            "Unable to get the snmp session: "s + sessionConfig_.peername;
        throw snmp_exception(message);
    }
}

void Agent::closeTrapSession()
{
    if (trapSession_)
    {
        snmp_close(trapSession_);
    }
}

void Agent::createTrapPDU()
{
    trapPDU_ = snmp_pdu_create(SNMP_MSG_TRAP2);
    if (!trapPDU_)
    {
        constexpr auto message = "Failed to create notification PDU"sv;
        throw snmp_exception(message);
    }
}

void Agent::setSysUpTime()
{
    auto sysuptime = get_uptime();
    std::string sysuptimeStr = std::to_string(sysuptime);
    constexpr oid sysuptimeOID[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
    if (snmp_add_var(trapPDU_, sysuptimeOID, sizeof(sysuptimeOID) / sizeof(oid),
                     't', sysuptimeStr.c_str()))

    {
        constexpr auto message = "Failed to add the SNMP var: systime"sv;
        throw snmp_exception(message);
    }
}

void Agent::setTrapOID()
{
    constexpr oid trapOID[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
    constexpr oid id[] = {1, 3, 6, 1, 4, 1, 49871, 1, 0, 0, 1};
    if (!snmp_pdu_add_variable(trapPDU_, trapOID, sizeof(trapOID) / sizeof(oid),
                               ASN_OBJECT_ID, id, sizeof(id)))
    {
        snmp_free_pdu(trapPDU_);
        constexpr auto message = "Failed to add the SNMP var: trapOID"sv;
        throw snmp_exception(message);
    }
}

void Agent::setTrapMessage(std::string&& message)
{
    std::vector<oid> messageOID = {1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 1};
    if (!snmp_pdu_add_variable(trapPDU_, messageOID.data(), messageOID.size(),
                               ASN_OCTET_STR, message.c_str(), message.size()))
    {
        snmp_free_pdu(trapPDU_);
        constexpr auto message = "Failed to add the SNMP var: message"sv;
        throw snmp_exception(message);
    }
}

void Agent::sendPDU()
{
    if (!snmp_send(trapSession_, trapPDU_))
    {
        constexpr auto message = "Failed to send the snmp trap"sv;
        throw snmp_exception(message);
    }
}

void Agent::sendTrap(std::string&& message)
{
    createTrapSession();
    createTrapPDU();
    setTrapOID();
    setSysUpTime();
    setTrapMessage(std::forward<std::string>(message));
    sendPDU();
    closeTrapSession();
}

} // namespace snmp