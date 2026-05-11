package com.safetech.otshield.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Generic audit-trail entry. Every settings/configuration change, security
 * action (login, logout, role change), or alert state change should produce
 * one row here. Powers the Settings → Audit Log tab.
 */
@Entity
@Table(name = "audit_logs", indexes = {
    @Index(name = "idx_audit_actor", columnList = "actor"),
    @Index(name = "idx_audit_action", columnList = "action"),
    @Index(name = "idx_audit_created", columnList = "created_at")
})
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /** Username/email of who performed the action. "system" for automated. */
    @Column(name = "actor", nullable = false)
    private String actor;

    /** Short verb-style code: LOGIN, LOGOUT, USER_CREATED, ROLE_CHANGED,
     *  TOKEN_ROTATED, ALERT_ACKNOWLEDGED, SETTINGS_UPDATED, etc. */
    @Column(name = "action", nullable = false, length = 64)
    private String action;

    /** Human-readable description of what happened. */
    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    /** Optional resource identifier the action targeted (alert id, user id, ...). */
    @Column(name = "target_type", length = 64)
    private String targetType;

    @Column(name = "target_id", length = 255)
    private String targetId;

    /** Source IP of the actor (for login/audit purposes). */
    @Column(name = "source_ip", length = 64)
    private String sourceIp;

    /** Outcome — SUCCESS / FAILURE / PARTIAL. */
    @Column(name = "outcome", length = 32)
    private String outcome;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    public AuditLog() {}

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
        if (outcome == null) outcome = "SUCCESS";
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getActor() { return actor; }
    public void setActor(String actor) { this.actor = actor; }
    public String getAction() { return action; }
    public void setAction(String action) { this.action = action; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getTargetType() { return targetType; }
    public void setTargetType(String targetType) { this.targetType = targetType; }
    public String getTargetId() { return targetId; }
    public void setTargetId(String targetId) { this.targetId = targetId; }
    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }
    public String getOutcome() { return outcome; }
    public void setOutcome(String outcome) { this.outcome = outcome; }
    public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
}
