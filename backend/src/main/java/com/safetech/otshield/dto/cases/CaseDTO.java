package com.safetech.otshield.dto.cases;

import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.CaseCategory;
import com.safetech.otshield.model.CasePriority;
import com.safetech.otshield.model.CaseStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CaseDTO {
    private String id;
    private String caseNumber;
    private String title;
    private String description;

    private CaseStatus status;
    private CasePriority priority;
    private AlertSeverity severity;
    private CaseCategory category;

    private String assigneeId;
    private String assigneeName;
    private String reporterId;
    private String reporterName;

    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private LocalDateTime acknowledgedAt;
    private LocalDateTime containedAt;
    private LocalDateTime resolvedAt;
    private LocalDateTime closedAt;

    private String resolutionSummary;

    private Long mttAcknowledgeSeconds;
    private Long mttContainSeconds;
    private Long mttResolveSeconds;

    private Set<String> tags;

    // Counts only on list view; full payload on detail
    private Integer linkedAlertCount;
    private Integer artifactCount;
    private Integer timelineCount;

    // Populated on detail view only
    private List<String> linkedAlertIds;
    private List<CaseTimelineEntryDTO> timeline;
    private List<CaseArtifactDTO> artifacts;
}
