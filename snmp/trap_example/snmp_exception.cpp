#include "snmp_exception.h"

namespace snmp
{

snmp_exception::snmp_exception(std::string_view message) : message_{ message }
{
    // TODO Try to extract error message from net-snmp library
}

const char* snmp_exception::what() const noexcept
{
    return message_.c_str();
}

} // namespace snmp