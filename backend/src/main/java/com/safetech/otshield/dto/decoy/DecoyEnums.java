package com.safetech.otshield.dto.decoy;

/**
 * Shared enumerations used by the Decoy Layer DTOs.
 * Keeping them in one file to make the contract easy to read in one place.
 */
public final class DecoyEnums {

    private DecoyEnums() {}

    /** Industrial protocols supported by the deception fabric. */
    public enum DecoyProtocol {
        MODBUS,
        S7,
        DNP3,
        ETHERNET_IP,
        OPC_UA
    }

    /** Lifecycle status of a decoy instance. */
    public enum DecoyStatus {
        RUNNING,
        STOPPED,
        DEGRADED,
        STARTING,
        STOPPING
    }

    /** Engagement (attacker session) status. */
    public enum EngagementStatus {
        ACTIVE,
        IDLE,
        CLOSED
    }

    /** Generic severity used for engagements and events. */
    public enum Severity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    /** Direction of an engagement event from the decoy's point of view. */
    public enum EventDirection {
        INBOUND,
        OUTBOUND
    }

    /** Response actions the SOC can take from the Decoy Layer page. */
    public enum DecoyActionType {
        BLOCK_IP,
        UNBLOCK_IP,
        QUARANTINE_SESSION,
        ADD_HONEYTOKEN,
        ADD_BREADCRUMB,
        ESCALATE_ALERT,
        TAG_ATTACKER,
        START_INSTANCE,
        STOP_INSTANCE
    }

    /** Result of an applied response action. */
    public enum DecoyActionStatus {
        APPLIED,
        FAILED,
        PENDING
    }
}
