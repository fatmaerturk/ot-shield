package com.safetech.otshield.dto.decoy;

import lombok.Data;
import java.util.Map;

/** Request body for POST /api/decoy/actions. */
@Data
public class DecoyActionRequest {
    private DecoyEnums.DecoyActionType type;
    private String targetIp;          // for BLOCK_IP, UNBLOCK_IP, TAG_ATTACKER
    private String engagementId;      // for QUARANTINE_SESSION, ESCALATE_ALERT
    private String decoyInstanceId;   // for START_INSTANCE, STOP_INSTANCE, ADD_HONEYTOKEN
    private String reason;            // free-form justification (audit trail)
    private Map<String, Object> params; // action-specific extras (token name, breadcrumb path, ttl, ...)
}
