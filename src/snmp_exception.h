#include <exception>
#include <string>
#include <string_view>

namespace snmp
{

class snmp_exception : public std::exception
{
public:
    snmp_exception(std::string_view message);
    const char* what() const noexcept override;
private:
    std::string message_;
};

}
