package com.safetech.otshield.mapper;

import com.safetech.otshield.model.Alert;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "alert_escalations")
public class AlertEscalation {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "alert_id", nullable = false)
    private Alert alert;

    @Column(name = "escalation_level", nullable = false)
    private Integer escalationLevel = 1;

    @Column(name = "escalated_from")
    private String escalatedFrom;

    @Column(name = "escalated_to", nullable = false)
    private String escalatedTo;

    @Column(name = "escalation_reason", columnDefinition = "TEXT")
    private String escalationReason;

    @Column(name = "escalation_time", nullable = false)
    private LocalDateTime escalationTime;

    @Column(name = "response_time")
    private LocalDateTime responseTime;

    @Column(name = "resolution_time")
    private LocalDateTime resolutionTime;

    @Column(name = "status", nullable = false)
    @Enumerated(EnumType.STRING)
    private EscalationStatus status = EscalationStatus.ACTIVE;

    @Column(name = "timeout_minutes")
    private Integer timeoutMinutes = 30;

    @Column(name = "auto_escalate")
    private Boolean autoEscalate = true;

    @Column(name = "escalation_policy")
    private String escalationPolicy;

    @Column(name = "notes", columnDefinition = "TEXT")
    private String notes;

    @PrePersist
    protected void onCreate() {
        if (escalationTime == null) {
            escalationTime = LocalDateTime.now();
        }
    }

    public enum EscalationStatus {
        ACTIVE("Active"),
        RESPONDED("Responded"),
        RESOLVED("Resolved"),
        TIMEOUT("Timeout"),
        CANCELLED("Cancelled");

        private final String displayName;

        EscalationStatus(String displayName) {
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
} 