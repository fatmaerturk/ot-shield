package com.safetech.otshield.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;

/**
 * NIS2 Email Notification entity representing email templates and rules
 * Maps to the nis2_email_notifications table in the database
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "nis2_email_notifications")
public class NIS2EmailNotification {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String subject;

    @Column(columnDefinition = "TEXT")
    private String body;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private NotificationType notificationType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private NotificationStatus status;

    @Column(name = "is_template")
    private Boolean isTemplate;

    @Column(name = "template_id")
    private String templateId;

    @ElementCollection
    @CollectionTable(name = "nis2_notification_recipients", joinColumns = @JoinColumn(name = "notification_id"))
    @Column(name = "recipient")
    private List<String> recipients;

    @ElementCollection
    @CollectionTable(name = "nis2_notification_cc", joinColumns = @JoinColumn(name = "notification_id"))
    @Column(name = "cc_recipient")
    private List<String> ccRecipients;

    @ElementCollection
    @CollectionTable(name = "nis2_notification_bcc", joinColumns = @JoinColumn(name = "notification_id"))
    @Column(name = "bcc_recipient")
    private List<String> bccRecipients;

    @Column(name = "trigger_condition")
    private String triggerCondition;

    @Column(name = "schedule_cron")
    private String scheduleCron;

    @Column(name = "last_sent_at")
    private LocalDateTime lastSentAt;

    @Column(name = "next_send_at")
    private LocalDateTime nextSendAt;

    @Column(name = "sent_count")
    private Integer sentCount;

    @Column(name = "failure_count")
    private Integer failureCount;

    @Column(name = "max_retries")
    private Integer maxRetries;

    @Column(name = "retry_interval_minutes")
    private Integer retryIntervalMinutes;

    @Column(columnDefinition = "TEXT")
    private String customFields;

    @ElementCollection
    @CollectionTable(name = "nis2_notification_tags", joinColumns = @JoinColumn(name = "notification_id"))
    @Column(name = "tag")
    private List<String> tags;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "updated_by")
    private String updatedBy;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
        if (sentCount == null) sentCount = 0;
        if (failureCount == null) failureCount = 0;
        if (maxRetries == null) maxRetries = 3;
        if (retryIntervalMinutes == null) retryIntervalMinutes = 15;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public enum NotificationType {
        COMPLIANCE_CHANGE,
        ASSESSMENT_DUE,
        CRITICAL_FINDING,
        REMEDIATION_COMPLETE,
        REPORT_GENERATED,
        AUDIT_SCHEDULED,
        TRAINING_REMINDER,
        POLICY_UPDATE,
        INCIDENT_ALERT,
        CUSTOM
    }

    public enum NotificationStatus {
        ACTIVE,
        INACTIVE,
        DRAFT,
        ARCHIVED
    }
} 