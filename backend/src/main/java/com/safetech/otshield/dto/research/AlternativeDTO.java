package com.safetech.otshield.dto.research;

import com.safetech.otshield.service.assistant.AlternativesService.Alternative;
import com.safetech.otshield.service.assistant.AssistantService.Confidence;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Outbound shape of one "alternative theory" attached to an assistant
 * message. Confidence is returned as its enum name so the frontend can
 * reuse the same AssistantConfidence union it already uses for the
 * primary-answer pill.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AlternativeDTO {
    private int index;
    private String hypothesis;
    private String rationale;
    private String confidence;

    public static AlternativeDTO from(Alternative a) {
        return AlternativeDTO.builder()
                .index(a.index())
                .hypothesis(a.hypothesis())
                .rationale(a.rationale())
                .confidence(a.confidence() == null ? Confidence.MEDIUM.name() : a.confidence().name())
                .build();
    }
}
