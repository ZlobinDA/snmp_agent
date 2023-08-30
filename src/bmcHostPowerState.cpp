#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "bmcHostPowerState.h"

/* the variable we want to tie an OID to.  The agent will handle all
 * * GET and SET requests to this variable changing it's value as needed.
 */

static long bmcHostPowerState = 2;


/* Function: handler_nstAgentSubagentObject
 * Purpose: callback handler for the request to an OID of this subagent
 * 
 */
int handler_bmcHostPowerState(
	netsnmp_mib_handler *mibHandler,
	netsnmp_handler_registration *handlerRegistration,
	netsnmp_agent_request_info *agentRequestInfo,
	netsnmp_request_info *requestInfo)
{
    switch(agentRequestInfo->mode)
    {
        case MODE_GET:
        {
            ++bmcHostPowerState;
            break;
        }
        case MODE_GETNEXT:
            break;
        case MODE_GETBULK:
            break;
        case MODE_SET_RESERVE1:
            break;
        case MODE_SET_RESERVE2:
            break;
        case MODE_SET_FREE:
            break;
        case MODE_SET_ACTION:
            break;
        case MODE_SET_COMMIT:
            break;
        case MODE_SET_UNDO:
            break;
        default:
            return SNMP_ERR_GENERR;
    }

    return SNMP_ERR_NOERROR;

}

void init_bmcHostPowerState()
{
	static oid bmcHostPowerState_oid[] = { 1, 3, 6, 1, 4, 1, 56392, 0, 1, 0 };

	netsnmp_register_read_only_long_instance(
		"bmcHostPowerState",
		bmcHostPowerState_oid, OID_LENGTH(bmcHostPowerState_oid),
		&bmcHostPowerState,
		handler_bmcHostPowerState);

}
