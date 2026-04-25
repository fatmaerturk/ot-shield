package com.safetech.otshield.model;

public enum CasePriority {
    CRITICAL("Critical", 1),
    HIGH("High", 2),
    MEDIUM("Medium", 3),
    LOW("Low", 4);

    private final String displayName;
    private final int weight;

    CasePriority(String displayName, int weight) {
        this.displayName = displayName;
        this.weight = weight;
    }

    public String getDisplayName() {
        return displayName;
    }

    public int getWeight() {
        return weight;
    }
}
