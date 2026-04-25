package com.safetech.otshield.dto.fakehmi;

/**
 * Enumerations shared across fake-HMI DTOs. A fake HMI is a deception asset
 * that masquerades as a genuine Human-Machine Interface in an OT facility.
 * Classified by industrial scenario and visual "vendor" styling.
 */
public final class FakeHmiEnums {

    private FakeHmiEnums() {}

    /** Process/industry scenario the fake HMI simulates. */
    public enum HmiScenarioType {
        WATER_TREATMENT,
        SUBSTATION,
        OIL_GAS,
        MANUFACTURING
    }

    /** Visual styling the HMI front-end renders with. Purely cosmetic. */
    public enum HmiVariantStyle {
        SIEMENS,
        ROCKWELL,
        SCHNEIDER,
        GENERIC
    }

    /** Lifecycle state of the fake HMI. */
    public enum HmiStatus {
        RUNNING,
        STOPPED,
        DEGRADED
    }

    /** Severity level for an alarm raised inside a fake HMI. */
    public enum HmiAlarmSeverity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    /** Type of attacker interaction recorded against an HMI. */
    public enum HmiInteractionType {
        PAGE_VIEW,       // attacker opened the HMI page
        LOGIN_ATTEMPT,   // tried a credential
        CONTROL_WRITE,   // attempted to toggle/write a tag
        ALARM_ACK,       // acknowledged an alarm
        DATA_POLL,       // read values repeatedly
        CONFIG_PROBE     // explored config/download pages
    }
}
