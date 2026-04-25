package com.safetech.otshield.model;

public enum CaseStatus {
    NEW("New"),
    TRIAGING("Triaging"),
    INVESTIGATING("Investigating"),
    CONTAINED("Contained"),
    RESOLVED("Resolved"),
    FALSE_POSITIVE("False Positive"),
    CLOSED("Closed");

    private final String displayName;

    CaseStatus(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    public boolean isTerminal() {
        return this == RESOLVED || this == FALSE_POSITIVE || this == CLOSED;
    }
}
