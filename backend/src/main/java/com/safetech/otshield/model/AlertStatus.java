package com.safetech.otshield.model;

public enum AlertStatus {
    NEW("New"),
    ACKNOWLEDGED("Acknowledged"),
    IN_PROGRESS("In Progress"),
    ESCALATED("Escalated"),
    RESOLVED("Resolved"),
    CLOSED("Closed"),
    FALSE_POSITIVE("False Positive");

    private final String displayName;

    AlertStatus(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
} 