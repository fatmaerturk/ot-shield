package com.safetech.otshield.dto.research;

import com.safetech.otshield.model.research.ResearchThread;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/** Outbound projection for a thread row (used in both list and detail). */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ResearchThreadDTO {
    private String id;
    private String title;
    private String lastQuestion;
    private int messageCount;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public static ResearchThreadDTO from(ResearchThread t) {
        return ResearchThreadDTO.builder()
                .id(t.getId())
                .title(t.getTitle())
                .lastQuestion(t.getLastQuestion())
                .messageCount(t.getMessageCount())
                .createdAt(t.getCreatedAt())
                .updatedAt(t.getUpdatedAt())
                .build();
    }
}
