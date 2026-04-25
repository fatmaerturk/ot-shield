package com.safetech.otshield.dto.fakehmi;

import lombok.Data;
import java.time.Instant;

/**
 * A single attacker interaction with a fake HMI. Recorded for SOC visibility.
 */
@Data
public class HmiInteractionDTO {
    private String id;
    private String hmiId;
    private Instant ts;
    private String attackerIp;
    private String attackerCountry;     // ISO-2 when resolvable
    private FakeHmiEnums.HmiInteractionType type;
    private String target;              // tag name / URL path / screen name
    private String payload;             // truncated payload (credential, value, command...)
    private Boolean blocked;            // was this attempt rejected server-side?
    private String userAgent;           // optional
}
