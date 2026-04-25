package com.safetech.otshield.dto.cases;

import com.safetech.otshield.model.CaseTimelineEntryType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CaseTimelineEntryDTO {
    private String id;
    private String caseId;
    private LocalDateTime ts;
    private CaseTimelineEntryType entryType;
    private String actorId;
    private String actorName;
    private String content;
    private String metadataJson;
}
