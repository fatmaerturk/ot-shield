package com.safetech.otshield.dto.cases;

import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.CaseCategory;
import com.safetech.otshield.model.CasePriority;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateCaseRequest {
    private String title;
    private String description;
    private CasePriority priority;
    private AlertSeverity severity;
    private CaseCategory category;
    private String assigneeId;
    private String assigneeName;
    private String reporterId;
    private String reporterName;
    private Set<String> tags;

    /** Optional - if present, link these alerts and seed title/severity from the first one. */
    private List<String> alertIds;
}
