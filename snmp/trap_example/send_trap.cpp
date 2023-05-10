#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <iostream>
#include <vector>

void sendTrap()
{
    // Initialize the SNMP library
    init_snmp("snmpapp");

    // Make struct that holdds infomation about who we're going to  be talking.
    snmp_session session;
    snmp_sess_init(&session);

    constexpr auto peername = "127.0.0.1:162";
    session.peername = const_cast<char*>(peername);

    session.version = SNMP_VERSION_2c;

    constexpr auto community = "public";
    session.community = reinterpret_cast<u_char*>(const_cast<char*>(community));
    session.community_len = strlen(community);

    session.callback = nullptr;
    session.callback_magic = nullptr;

    // Create the session
    auto ss = snmp_add(
        &session, netsnmp_transport_open_client("snmptrap", session.peername),
        nullptr, nullptr);
    if (!ss)
    {
        std::cerr << "Unable to get the snmp session: " << peername << "\n";
    }

    // Create the SNMP trap PDU
    auto pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
    if (!pdu)
    {
        std::cerr << "Failed to create notification PDU\n";
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
    }

    // Add trap message
    std::vector<oid> messageOID = {1, 3, 6, 1, 4, 1, 49871, 1, 0, 1, 1};
    std::string message = "Test trap";
    if (!snmp_pdu_add_variable(pdu, messageOID.data(), messageOID.size(),
                               ASN_OCTET_STR, message.c_str(), message.size()))
    {
        std::cerr << "Failed to add the SNMP var: message\n";
        snmp_free_pdu(pdu);
    }

    // Send the trap
    if (!snmp_send(ss, pdu))
    {
        std::cerr << "Failed to send the snmp trap\n";
    }

    // Close the session
    snmp_close(ss);

    // Shutdown the SNMP application
    snmp_shutdown("snmpapp");
}
