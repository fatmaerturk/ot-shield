package com.safetech.otshield.dto.research;

import com.safetech.otshield.model.research.ResearchFinding;
import com.safetech.otshield.service.assistant.AssistantService.Citation;
import com.safetech.otshield.service.research.ThreadService;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/** Outbound projection for a curated finding. */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ResearchFindingDTO {
    private String id;
    private String title;
    private String text;
    private List<Citation> citations;
    private String sourceThreadId;
    private String sourceMessageId;
    private String tags;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public static ResearchFindingDTO from(ResearchFinding f, ThreadService threadService) {
        return ResearchFindingDTO.builder()
                .id(f.getId())
                .title(f.getTitle())
                .text(f.getText())
                .citations(threadService.parseCitations(f.getCitationsJson()))
                .sourceThreadId(f.getSourceThreadId())
                .sourceMessageId(f.getSourceMessageId())
                .tags(f.getTags())
                .createdAt(f.getCreatedAt())
                .updatedAt(f.getUpdatedAt())
                .build();
    }
}
