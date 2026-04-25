package com.safetech.otshield.dto.cases;

import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.CaseCategory;
import com.safetech.otshield.model.CasePriority;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdateCaseRequest {
    // Any null field is ignored.
    private String title;
    private String description;
    private CasePriority priority;
    private AlertSeverity severity;
    private CaseCategory category;
    private Set<String> tags;
    private String resolutionSummary;
}
