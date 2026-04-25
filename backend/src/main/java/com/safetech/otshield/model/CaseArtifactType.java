package com.safetech.otshield.model;

public enum CaseArtifactType {
    IP("IP Address"),
    DOMAIN("Domain"),
    URL("URL"),
    HASH("File Hash"),
    FILE("File"),
    PCAP("PCAP Reference"),
    HMI_INTERACTION("HMI Interaction"),
    CVE("CVE"),
    USER_ACCOUNT("User Account"),
    PROCESS("Process"),
    REGISTRY_KEY("Registry Key"),
    COMMAND("Command"),
    OTHER("Other");

    private final String displayName;

    CaseArtifactType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
