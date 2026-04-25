package com.safetech.otshield.dto.cases;

import com.safetech.otshield.model.CaseArtifactType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CaseArtifactRequest {
    private CaseArtifactType artifactType;
    private String value;
    private String label;
    private String description;
    private Boolean malicious;
    private String actorName;
}
