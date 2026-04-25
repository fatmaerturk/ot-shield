package com.safetech.otshield.mapper;

import com.safetech.otshield.model.AlertType;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "alert_rules")
public class AlertRule {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false, unique = true)
    private String name;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AlertSeverity severity;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AlertType type;

    @Column(nullable = false)
    private Boolean enabled = true;

    @Column(name = "rule_condition", columnDefinition = "TEXT", nullable = false)
    private String condition;

    @Column(name = "rule_action", columnDefinition = "TEXT")
    private String action;

    @Column(name = "threshold_value")
    private Integer thresholdValue;

    @Column(name = "time_window_minutes")
    private Integer timeWindowMinutes;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "updated_by")
    private String updatedBy;

    @ElementCollection
    @CollectionTable(name = "alert_rule_tags", joinColumns = @JoinColumn(name = "rule_id"))
    @Column(name = "tag")
    private List<String> tags;

    @Column(name = "priority")
    private Integer priority = 0;

    @Column(name = "category")
    private String category;

    @Column(name = "source_systems")
    private String sourceSystems;

    @Column(name = "suppression_enabled")
    private Boolean suppressionEnabled = false;

    @Column(name = "suppression_duration_minutes")
    private Integer suppressionDurationMinutes = 60;

    @Column(name = "notification_channels")
    private String notificationChannels;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
} 