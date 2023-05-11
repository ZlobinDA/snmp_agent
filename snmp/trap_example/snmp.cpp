#include "snmp.h"

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <iostream>
#include <vector>

namespace snmp
{
void sendTrap(const std::string& snmpVersion, const bool isAuthenticationKeySet,
              const bool isEncryptionKeySet)
{
    using namespace std::string_literals;
    using namespace std::string_view_literals;
    constexpr std::string_view snmpV2c = "SNMPv2c"sv;
    constexpr std::string_view snmpV3 = "SNMPv3"sv;

    auto version = SNMP_VERSION_3;
    if (snmpVersion == snmpV2c)
    {
        version = SNMP_VERSION_2c;
    }
    else if (snmpVersion == snmpV3)
    {
        version = SNMP_VERSION_3;
    }

    // Initialize the SNMP library
    init_snmp("snmpapp");

    // Make struct that holdds infomation about who we're going to  be talking.
    snmp_session session;
    snmp_sess_init(&session);

    constexpr auto peername = "127.0.0.1:162";
    session.peername = const_cast<char*>(peername);

    if (version == SNMP_VERSION_3)
    {
        session.version = SNMP_VERSION_3;
        std::cerr << "snmp: session.version: " << session.version << "\n";

        std::string username;
        auto level = SNMP_SEC_LEVEL_NOAUTH;
        unsigned char engineID[5] = {0x0, 0x0, 0x0, 0x0, 0x0};
        if (!isAuthenticationKeySet && !isEncryptionKeySet)
        {
            level = SNMP_SEC_LEVEL_NOAUTH;
            engineID[0] = 0x01;
            engineID[1] = 0x02;
            engineID[2] = 0x03;
            engineID[3] = 0x04;
            engineID[4] = 0x05;
            username = "user1"s;
        }
        else if (isAuthenticationKeySet && !isEncryptionKeySet)
        {
            level = SNMP_SEC_LEVEL_AUTHNOPRIV;
            engineID[0] = 0x02;
            engineID[1] = 0x03;
            engineID[2] = 0x04;
            engineID[3] = 0x05;
            engineID[4] = 0x06;
            username = "user2"s;

            session.securityAuthProto = usmHMACSHA1AuthProtocol;
            session.securityAuthProtoLen =
                sizeof(usmHMACSHA1AuthProtocol) / sizeof(oid);

            const auto securityAuthKey = "authPass";
            session.securityAuthKeyLen = USM_AUTH_KU_LEN;

            if (generate_Ku(session.securityAuthProto,
                            session.securityAuthProtoLen,
                            (u_char*)(securityAuthKey), strlen(securityAuthKey),
                            session.securityAuthKey,
                            &session.securityAuthKeyLen) != SNMPERR_SUCCESS)
            {
                snmp_log(
                    LOG_ERR,
                    "Error generating Ku from authentication pass phrase. \n");
                return;
            }
        }
        else if (isAuthenticationKeySet && isEncryptionKeySet)
        {
            level = SNMP_SEC_LEVEL_AUTHNOPRIV;
            engineID[0] = 0x03;
            engineID[1] = 0x04;
            engineID[2] = 0x05;
            engineID[3] = 0x06;
            engineID[4] = 0x07;
            username = "user3"s;

            session.securityAuthProto = usmHMACSHA1AuthProtocol;
            session.securityAuthProtoLen =
                sizeof(usmHMACSHA1AuthProtocol) / sizeof(oid);

            const auto securityAuthKey = "authPass";
            session.securityAuthKeyLen = USM_AUTH_KU_LEN;

            if (generate_Ku(session.securityAuthProto,
                            session.securityAuthProtoLen,
                            (u_char*)(securityAuthKey), strlen(securityAuthKey),
                            session.securityAuthKey,
                            &session.securityAuthKeyLen) != SNMPERR_SUCCESS)
            {
                snmp_log(
                    LOG_ERR,
                    "Error generating Ku from authentication pass phrase. \n");
                return;
            }

            session.securityPrivProto = usmAESPrivProtocol;
            session.securityPrivProtoLen =
                sizeof(usmAESPrivProtocol) / sizeof(oid);

            const auto securityPrivKey = "privPass";
            session.securityPrivKeyLen = USM_PRIV_KU_LEN;

            if (generate_Ku(session.securityAuthProto,
                            session.securityAuthProtoLen,
                            (u_char*)(securityPrivKey), strlen(securityPrivKey),
                            session.securityPrivKey,
                            &session.securityPrivKeyLen) != SNMPERR_SUCCESS)
            {
                char* error = nullptr;
                snmp_perror(error);
                std::cerr << "Error generating Ku from encription pass phrase: "
                          << error << "\n";
                return;
            }
        }

        session.securityEngineID = const_cast<unsigned char*>(engineID);
        session.securityEngineIDLen = sizeof(engineID) / sizeof(engineID[0]);

        session.securityName = const_cast<char*>(username.data());
        session.securityNameLen = strlen(session.securityName);

        session.securityLevel = level;
    }
    else if (version == SNMP_VERSION_2c)
    {
        std::cerr << "snmp: version 2c is used" << std::endl;
        session.version = SNMP_VERSION_2c;

        constexpr auto community = "public";
        session.community =
            reinterpret_cast<u_char*>(const_cast<char*>(community));
        session.community_len = strlen(community);
    }

    session.callback = nullptr;
    session.callback_magic = nullptr;

    // Create the session
    auto ss = snmp_add(
        &session, netsnmp_transport_open_client("snmptrap", session.peername),
        nullptr, nullptr);
    if (!ss)
    {
        std::cerr << "Unable to get the snmp session: " << peername << "\n";
        return;
    }

    // Create the SNMP trap PDU
    auto pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
    if (!pdu)
    {
        std::cerr << "Failed to create notification PDU\n";
        return;
    }

    // Add the sysUpTime.0 to the trap PDU
    auto sysuptime = get_uptime();
    std::string sysuptimeStr = std::to_string(sysuptime);
    oid sysuptimeOID[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};

    if (snmp_add_var(pdu, sysuptimeOID, sizeof(sysuptimeOID) / sizeof(oid), 't',
                     sysuptimeStr.c_str()))

    {
        std::cerr << "Failed to add the SNMP var: systime\n";
        snmp_free_pdu(pdu);
        return;
    }

    // Add the trapOID.0
    std::vector<oid> trapOID = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
    std::vector<oid> id = {1, 3, 6, 1, 4, 1, 49871, 1, 0, 0, 1};
    if (!snmp_pdu_add_variable(pdu, trapOID.data(), trapOID.size(),
                               ASN_OBJECT_ID, id.data(),
                               id.size() * sizeof(id[0])))
    {
        std::cerr << "Failed to add the SNMP var: trapOID\n";
        snmp_free_pdu(pdu);
        return;
    }

    // Add trap message
    std::vector<oid> messageOID = {1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 1};
    std::string message = "Test trap ("s + "version: "s + snmpVersion +
                          " auth: "s + std::to_string(isAuthenticationKeySet) +
                          " priv: "s + std::to_string(isEncryptionKeySet) +
                          ")"s;
    if (!snmp_pdu_add_variable(pdu, messageOID.data(), messageOID.size(),
                               ASN_OCTET_STR, message.c_str(), message.size()))
    {
        std::cerr << "Failed to add the SNMP var: message\n";
        snmp_free_pdu(pdu);
        return;
    }

    // Send the trap
    if (!snmp_send(ss, pdu))
    {
        std::cerr << "Failed to send the snmp trap: "
                  << "\n";
        return;
    }

    // Close the session
    snmp_close(ss);

    // Shutdown the SNMP application
    snmp_shutdown("snmpapp");
}
} // namespace snmp