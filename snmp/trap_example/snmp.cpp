#include "snmp.h"
#include "snmp_exception.h"

#include <sstream>
#include <vector>

namespace snmp
{

Agent::Agent(std::string_view appName) : appName_{appName}
{
    init_snmp(appName_.c_str());

    snmp_sess_init(&session_);
    session_.callback = nullptr;
    session_.callback_magic = nullptr;
}

Agent::~Agent()
{
    snmp_shutdown(appName_.c_str());
}

void Agent::setVersion(std::string_view version)
{
    if (version == version2c)
    {
        session_.version = SNMP_VERSION_2c;
    }
    else if (version == snmpV3)
    {
        session_.version = SNMP_VERSION_3;
    }
}

void Agent::setCommunityString(std::string_view community)
{
    session_.community =
        reinterpret_cast<u_char*>(const_cast<char*>(community.data()));
    session_.community_len = community.size();
}

void Agent::setUsername(std::string_view username)
{
    session_.securityName = const_cast<char*>(username.data());
    session_.securityNameLen = strlen(session_.securityName);
}

void Agent::setPeername(std::string_view peername)
{
    session_.peername = const_cast<char*>(peername.data());
}

void Agent::setEngineID(std::string_view engineID)
{
    static std::vector<unsigned char> securityEngineID = {0x00, 0x00, 0x00,
                                                          0x00, 0x00};
    securityEngineID = getBytesFromEngineIDString(engineID);
    session_.securityEngineID = securityEngineID.data();
    session_.securityEngineIDLen = securityEngineID.size();
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

void Agent::setSecurityLevel(int level)
{
    session_.securityLevel = level;
}

void Agent::setAuthProtocol(std::string_view protocol)
{
    // TODO Add other auth protocols
    session_.securityAuthProto = usmHMACSHA1AuthProtocol;
    session_.securityAuthProtoLen =
        sizeof(usmHMACSHA1AuthProtocol) / sizeof(oid);
}

void Agent::setAuthKey(std::string_view key)
{
    session_.securityAuthKeyLen = USM_AUTH_KU_LEN;
    auto securityAuthKey =
        reinterpret_cast<u_char*>(const_cast<char*>(key.data()));
    auto securityAuthKeyLen = key.size();
    if (generate_Ku(session_.securityAuthProto, session_.securityAuthProtoLen,
                    securityAuthKey, securityAuthKeyLen,
                    session_.securityAuthKey,
                    &session_.securityAuthKeyLen) != SNMPERR_SUCCESS)
    {
        constexpr auto message =
            "Error generating Ku from authentication pass phrase"sv;
        throw snmp_exception(message);
    }
}

void Agent::setPrivProtocol(std::string_view protocol)
{
    // TODO Add other priv protocols
    session_.securityPrivProto = usmAESPrivProtocol;
    session_.securityPrivProtoLen = sizeof(usmAESPrivProtocol) / sizeof(oid);
}

void Agent::setPrivKey(std::string_view key)
{
    session_.securityPrivKeyLen = USM_PRIV_KU_LEN;
    auto securityPrivKey = reinterpret_cast<u_char*>(const_cast<char*>(key.data()));
    auto securityPrivKeyLen = key.size();
    if (generate_Ku(session_.securityAuthProto, session_.securityAuthProtoLen,
                    securityPrivKey, securityPrivKeyLen,
                    session_.securityPrivKey,
                    &session_.securityPrivKeyLen) != SNMPERR_SUCCESS)
    {
        constexpr auto message =
            "Error generating Ku from encription pass phrase"sv;
        throw snmp_exception(message);
    }
}

void Agent::sendTrap(const std::string&& message)
{
    // Create the session
    netsnmp_session* session = snmp_add(
        &session_, netsnmp_transport_open_client("snmptrap", session_.peername),
        nullptr, nullptr);
    if (!session)
    {
        using namespace std::string_literals;
        const std::string message = "Unable to get the snmp session: "s + std::string(session_.peername);
        throw snmp_exception(message);
    }

    // Create the SNMP trap PDU
    netsnmp_pdu* pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
    if (!pdu)
    {
        constexpr auto message = "Failed to create notification PDU"sv;
        throw snmp_exception(message);
    }

    // Add the sysUpTime.0 to the trap PDU
    auto sysuptime = get_uptime();
    std::string sysuptimeStr = std::to_string(sysuptime);
    oid sysuptimeOID[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};

    if (snmp_add_var(pdu, sysuptimeOID, sizeof(sysuptimeOID) / sizeof(oid), 't',
                     sysuptimeStr.c_str()))

    {
        constexpr auto message = "Failed to add the SNMP var: systime"sv;
        throw snmp_exception(message);
    }

    // Add the trapOID.0
    std::vector<oid> trapOID = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
    std::vector<oid> id = {1, 3, 6, 1, 4, 1, 49871, 1, 0, 0, 1};
    if (!snmp_pdu_add_variable(pdu, trapOID.data(), trapOID.size(),
                               ASN_OBJECT_ID, id.data(),
                               id.size() * sizeof(id[0])))
    {
        snmp_free_pdu(pdu);
        constexpr auto message = "Failed to add the SNMP var: trapOID"sv;
        throw snmp_exception(message);
    }

    // Add trap message
    std::vector<oid> messageOID = {1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 1};
    if (!snmp_pdu_add_variable(pdu, messageOID.data(), messageOID.size(),
                               ASN_OCTET_STR, message.c_str(), message.size()))
    {
        snmp_free_pdu(pdu);
        constexpr auto message = "Failed to add the SNMP var: message"sv;
        throw snmp_exception(message);
    }

    // Send the trap
    if (!snmp_send(session, pdu))
    {
        constexpr auto message = "Failed to send the snmp trap"sv;
        throw snmp_exception(message);
    }

    // Close the session
    snmp_close(session);
}

} // namespace snmp