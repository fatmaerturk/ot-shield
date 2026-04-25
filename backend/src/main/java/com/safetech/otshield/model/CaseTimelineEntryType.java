package com.safetech.otshield.model;

public enum CaseTimelineEntryType {
    CREATED("Created"),
    STATUS_CHANGE("Status Change"),
    PRIORITY_CHANGE("Priority Change"),
    ASSIGNED("Assigned"),
    UNASSIGNED("Unassigned"),
    COMMENT("Comment"),
    ARTIFACT_ADDED("IOC Added"),
    ARTIFACT_REMOVED("IOC Removed"),
    ALERT_LINKED("Alert Linked"),
    ALERT_UNLINKED("Alert Unlinked"),
    TAG_ADDED("Tag Added"),
    TAG_REMOVED("Tag Removed"),
    ESCALATED("Escalated"),
    RESOLUTION("Resolution");

    private final String displayName;

    CaseTimelineEntryType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
