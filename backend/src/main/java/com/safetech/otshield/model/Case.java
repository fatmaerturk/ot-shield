package com.safetech.otshield.model;

import com.safetech.otshield.mapper.AlertSeverity;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "cases", indexes = {
        @Index(name = "idx_cases_status", columnList = "status"),
        @Index(name = "idx_cases_priority", columnList = "priority"),
        @Index(name = "idx_cases_assignee", columnList = "assignee_id"),
        @Index(name = "idx_cases_created_at", columnList = "created_at")
})
public class Case {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(name = "case_number", nullable = false, unique = true, length = 32)
    private String caseNumber;

    @Column(nullable = false, length = 256)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private CaseStatus status;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private CasePriority priority;

    @Enumerated(EnumType.STRING)
    @Column(length = 16)
    private AlertSeverity severity;

    @Enumerated(EnumType.STRING)
    @Column(length = 32)
    private CaseCategory category;

    @Column(name = "assignee_id", length = 128)
    private String assigneeId;

    @Column(name = "assignee_name", length = 128)
    private String assigneeName;

    @Column(name = "reporter_id", length = 128)
    private String reporterId;

    @Column(name = "reporter_name", length = 128)
    private String reporterName;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "acknowledged_at")
    private LocalDateTime acknowledgedAt;

    @Column(name = "contained_at")
    private LocalDateTime containedAt;

    @Column(name = "resolved_at")
    private LocalDateTime resolvedAt;

    @Column(name = "closed_at")
    private LocalDateTime closedAt;

    @Column(name = "resolution_summary", columnDefinition = "TEXT")
    private String resolutionSummary;

    @Column(name = "mtt_acknowledge_seconds")
    private Long mttAcknowledgeSeconds;

    @Column(name = "mtt_contain_seconds")
    private Long mttContainSeconds;

    @Column(name = "mtt_resolve_seconds")
    private Long mttResolveSeconds;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "case_tags", joinColumns = @JoinColumn(name = "case_id"))
    @Column(name = "tag", length = 64)
    @Builder.Default
    private Set<String> tags = new HashSet<>();

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "case_alerts",
            joinColumns = @JoinColumn(name = "case_id"),
            inverseJoinColumns = @JoinColumn(name = "alert_id")
    )
    @Builder.Default
    private Set<Alert> linkedAlerts = new HashSet<>();

    @OneToMany(mappedBy = "caseEntity", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderBy("ts ASC")
    @Builder.Default
    private List<CaseTimelineEntry> timeline = new ArrayList<>();

    @OneToMany(mappedBy = "caseEntity", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.LAZY)
    @OrderBy("addedAt DESC")
    @Builder.Default
    private List<CaseArtifact> artifacts = new ArrayList<>();

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
        if (status == null) status = CaseStatus.NEW;
        if (priority == null) priority = CasePriority.MEDIUM;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
}
