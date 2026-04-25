package com.safetech.otshield.dto.fakehmi;

import lombok.Data;

/**
 * Incoming request when an attacker (or SOC simulating one) hits a fake HMI
 * endpoint. Recorded into the interaction log.
 */
@Data
public class HmiInteractionRequest {
    private FakeHmiEnums.HmiInteractionType type;
    private String target;       // screen / tag / URL
    private String payload;      // credential, value written, query...
    private String attackerIp;   // optional override; if null, we take remote addr
    private String userAgent;
}
