package com.safetech.otshield.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;

/**
 * NIS2 Requirement entity representing compliance requirements
 * Maps to the nis2_requirements table in the database
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "nis2_requirements")
public class NIS2Requirement {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false)
    private String code;

    @Column(nullable = false)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(columnDefinition = "TEXT")
    private String detailedDescription;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RequirementCategory category;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RequirementCriticality criticality;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ComplianceStatus status;

    @Column(columnDefinition = "TEXT")
    private String evidence;

    @Column(columnDefinition = "TEXT")
    private String notes;

    @Column(name = "assigned_to")
    private String assignedTo;

    @Column(name = "due_date")
    private LocalDateTime dueDate;

    @Column(name = "last_assessment_date")
    private LocalDateTime lastAssessmentDate;

    @Column(name = "next_assessment_date")
    private LocalDateTime nextAssessmentDate;

    @Column(name = "compliance_score")
    private Integer complianceScore;

    @Column(name = "risk_score")
    private Integer riskScore;

    @ElementCollection
    @CollectionTable(name = "nis2_requirement_tags", joinColumns = @JoinColumn(name = "requirement_id"))
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
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public enum RequirementCategory {
        GOVERNANCE_AND_RISK_MANAGEMENT,
        ASSET_MANAGEMENT,
        ACCESS_CONTROL,
        THREAT_DETECTION,
        INCIDENT_RESPONSE,
        BUSINESS_CONTINUITY,
        SUPPLY_CHAIN_SECURITY,
        TRAINING_AND_AWARENESS,
        COMPLIANCE_AND_AUDIT
    }

    public enum RequirementCriticality {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW
    }

    public enum ComplianceStatus {
        COMPLIANT,
        NON_COMPLIANT,
        PARTIALLY_COMPLIANT,
        NOT_ASSESSED,
        IN_PROGRESS,
        EXEMPT
    }
} 