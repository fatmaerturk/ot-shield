package com.safetech.otshield.dto.cases;

import com.safetech.otshield.model.CaseArtifactType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CaseArtifactDTO {
    private String id;
    private String caseId;
    private CaseArtifactType artifactType;
    private String value;
    private String label;
    private String description;
    private String addedBy;
    private LocalDateTime addedAt;
    private Boolean malicious;
}
