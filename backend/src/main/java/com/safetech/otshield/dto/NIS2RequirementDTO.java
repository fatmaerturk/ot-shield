package com.safetech.otshield.dto;

import com.safetech.otshield.model.NIS2Requirement;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Data Transfer Object for NIS2Requirement entity
 * Used for API communication between frontend and backend
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class NIS2RequirementDTO {
    private String id;
    private String code;
    private String title;
    private String description;
    private String detailedDescription;
    private NIS2Requirement.RequirementCategory category;
    private NIS2Requirement.RequirementCriticality criticality;
    private NIS2Requirement.ComplianceStatus status;
    private String evidence;
    private String notes;
    private String assignedTo;
    private LocalDateTime dueDate;
    private LocalDateTime lastAssessmentDate;
    private LocalDateTime nextAssessmentDate;
    private Integer complianceScore;
    private Integer riskScore;
    private List<String> tags;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String createdBy;
    private String updatedBy;
} 