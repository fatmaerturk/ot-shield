package com.safetech.otshield.dto;

import com.safetech.otshield.model.NIS2ComplianceReport;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Data Transfer Object for NIS2ComplianceReport entity
 * Used for API communication between frontend and backend
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class NIS2ComplianceReportDTO {
    private String id;
    private String title;
    private String description;
    private NIS2ComplianceReport.ReportType reportType;
    private NIS2ComplianceReport.ReportStatus status;
    private Integer overallComplianceScore;
    private Integer totalRequirements;
    private Integer compliantRequirements;
    private Integer nonCompliantRequirements;
    private Integer partiallyCompliantRequirements;
    private Integer notAssessedRequirements;
    private Integer criticalFindingsCount;
    private Integer highRiskFindingsCount;
    private Integer mediumRiskFindingsCount;
    private Integer lowRiskFindingsCount;
    private String executiveSummary;
    private String detailedFindings;
    private String recommendations;
    private String remediationPlan;
    private LocalDateTime reportPeriodStart;
    private LocalDateTime reportPeriodEnd;
    private LocalDateTime generatedAt;
    private String generatedBy;
    private LocalDateTime approvedAt;
    private String approvedBy;
    private List<String> tags;
    private String filePath;
    private Long fileSize;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
} 