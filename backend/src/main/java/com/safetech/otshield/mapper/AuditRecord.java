package com.safetech.otshield.mapper;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "audit_records")
public class AuditRecord {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String username;      // who did the action
    private String actionType;    // e.g. FILTER_CHANGE, ROW_VIEW
    @Column(length = 1000)
    private String details;       // JSON or plain text describing filters/row id
    private Instant timestamp;    // when

    // Constructors
    public AuditRecord() {}

    public AuditRecord(String username, String actionType, String details, Instant timestamp) {
        this.username = username;
        this.actionType = actionType;
        this.details = details;
        this.timestamp = timestamp;
    }

    // Getters and setters...
    public Long getId() { return id; }
    public String getUsername() { return username; }
    public void setUsername(String u) { username = u; }
    public String getActionType() { return actionType; }
    public void setActionType(String a) { actionType = a; }
    public String getDetails() { return details; }
    public void setDetails(String d) { details = d; }
    public Instant getTimestamp() { return timestamp; }
    public void setTimestamp(Instant ts) { timestamp = ts; }
}