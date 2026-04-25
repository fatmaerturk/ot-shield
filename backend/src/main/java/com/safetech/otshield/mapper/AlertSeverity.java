package com.safetech.otshield.mapper;

public enum AlertSeverity {
    CRITICAL("Critical", 1),
    HIGH("High", 2),
    MEDIUM("Medium", 3),
    LOW("Low", 4),
    INFO("Info", 5);

    private final String displayName;
    private final int priority;

    AlertSeverity(String displayName, int priority) {
        this.displayName = displayName;
        this.priority = priority;
    }

    public String getDisplayName() {
        return displayName;
    }

    public int getPriority() {
        return priority;
    }

    @Override
    public String toString() {
        return displayName;
    }
} 