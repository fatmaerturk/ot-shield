package com.safetech.otshield.dto.decoy;

import lombok.Data;
import java.time.Instant;
import java.util.Map;

/** Response for POST /api/decoy/actions. */
@Data
public class DecoyActionResultDTO {
    private String id;
    private DecoyEnums.DecoyActionType type;
    private DecoyEnums.DecoyActionStatus status;
    private Instant appliedAt;
    private String appliedBy;
    private String message;             // human-readable confirmation
    private Map<String, Object> result; // action-specific payload (e.g. blockingRuleId)
}
