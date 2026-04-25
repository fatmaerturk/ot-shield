package com.safetech.otshield.dto.cases;

import com.safetech.otshield.model.CaseStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CaseTransitionRequest {
    private CaseStatus toStatus;
    private String note;
    private String resolutionSummary;
    private String actorName;
}
