package com.safetech.otshield.dto.cases;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CaseAssignRequest {
    private String assigneeId;
    private String assigneeName;
    private String actorName;
}
