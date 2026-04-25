package com.safetech.otshield.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;

/**
 * NIS2 Compliance Report entity representing compliance reports
 * Maps to the nis2_compliance_reports table in the database
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "nis2_compliance_reports")
public class NIS2ComplianceReport {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ReportType reportType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ReportStatus status;

    @Column(name = "overall_compliance_score")
    private Integer overallComplianceScore;

    @Column(name = "total_requirements")
    private Integer totalRequirements;

    @Column(name = "compliant_requirements")
    private Integer compliantRequirements;

    @Column(name = "non_compliant_requirements")
    private Integer nonCompliantRequirements;

    @Column(name = "partially_compliant_requirements")
    private Integer partiallyCompliantRequirements;

    @Column(name = "not_assessed_requirements")
    private Integer notAssessedRequirements;

    @Column(name = "critical_findings_count")
    private Integer criticalFindingsCount;

    @Column(name = "high_risk_findings_count")
    private Integer highRiskFindingsCount;

    @Column(name = "medium_risk_findings_count")
    private Integer mediumRiskFindingsCount;

    @Column(name = "low_risk_findings_count")
    private Integer lowRiskFindingsCount;

    @Column(columnDefinition = "TEXT")
    private String executiveSummary;

    @Column(columnDefinition = "TEXT")
    private String detailedFindings;

    @Column(columnDefinition = "TEXT")
    private String recommendations;

    @Column(columnDefinition = "TEXT")
    private String remediationPlan;

    @Column(name = "report_period_start")
    private LocalDateTime reportPeriodStart;

    @Column(name = "report_period_end")
    private LocalDateTime reportPeriodEnd;

    @Column(name = "generated_at", nullable = false)
    private LocalDateTime generatedAt;

    @Column(name = "generated_by")
    private String generatedBy;

    @Column(name = "approved_at")
    private LocalDateTime approvedAt;

    @Column(name = "approved_by")
    private String approvedBy;

    @ElementCollection
    @CollectionTable(name = "nis2_report_tags", joinColumns = @JoinColumn(name = "report_id"))
    @Column(name = "tag")
    private List<String> tags;

    @Column(name = "file_path")
    private String filePath;

    @Column(name = "file_size")
    private Long fileSize;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
        generatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public enum ReportType {
        EXECUTIVE_SUMMARY,
        DETAILED_ASSESSMENT,
        REMEDIATION_PLAN,
        QUARTERLY_REVIEW,
        ANNUAL_REVIEW,
        AUDIT_REPORT,
        COMPLIANCE_DASHBOARD
    }

    public enum ReportStatus {
        DRAFT,
        IN_REVIEW,
        APPROVED,
        PUBLISHED,
        ARCHIVED
    }
} 