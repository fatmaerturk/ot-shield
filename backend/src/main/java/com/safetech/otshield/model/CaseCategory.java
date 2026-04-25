package com.safetech.otshield.model;

public enum CaseCategory {
    MALWARE("Malware"),
    UNAUTHORIZED_ACCESS("Unauthorized Access"),
    POLICY_VIOLATION("Policy Violation"),
    ANOMALY("Anomaly"),
    RECON("Reconnaissance"),
    LATERAL_MOVEMENT("Lateral Movement"),
    OT_DISRUPTION("OT Disruption"),
    DATA_EXFIL("Data Exfiltration"),
    INSIDER_THREAT("Insider Threat"),
    OTHER("Other");

    private final String displayName;

    CaseCategory(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
