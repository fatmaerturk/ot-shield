package com.safetech.otshield.dto.attacker;

/**
 * Ordered kill-chain phases used to place a single attacker's actions on a
 * timeline. A pragmatic subset of MITRE ATT&amp;CK for ICS tactics, ordered from
 * earliest reconnaissance to process impact. The ordinal defines the canonical
 * left-to-right order in the UI progress bar.
 */
public enum KillChainPhase {
    RECON("Recon"),                       // Discovery (T0846) - scanning / enumeration
    INITIAL_ACCESS("Initial Access"),     // Internet-exposed device reached (T0883)
    DISCOVERY("Discovery"),               // Protocol / device-id probing of an internal target
    LATERAL_MOVEMENT("Lateral Movement"), // Reaching further into the OT segment
    EXECUTION("Execution"),               // Issuing control commands / function calls
    IMPACT("Impact");                     // Impair Process Control - writes (T0855, T0836)

    private final String displayName;

    KillChainPhase(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
