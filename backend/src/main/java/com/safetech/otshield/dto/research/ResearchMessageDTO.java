package com.safetech.otshield.dto.research;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.safetech.otshield.model.research.ResearchMessage;
import com.safetech.otshield.service.assistant.AlternativesService;
import com.safetech.otshield.service.assistant.AssistantService.Citation;
import com.safetech.otshield.service.assistant.SourceCrossCheckService.ConsistencyWarning;
import com.safetech.otshield.service.research.ThreadService;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

/**
 * Outbound projection for a single turn in a thread. Citations are
 * parsed from the stored JSON string into a typed list so the UI can
 * render them without re-doing JSON work client-side.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Slf4j
public class ResearchMessageDTO {

    /**
     * Shared mapper for decoding the persisted consistency JSON blob
     * back into typed {@link ConsistencyWarning} records. Instantiated
     * lazily per DTO because this class is a POJO without DI; the
     * overhead is negligible and keeps the API of {@link #from}
     * unchanged.
     */
    private static final ObjectMapper CONSISTENCY_MAPPER = new ObjectMapper();
    private String id;
    private String threadId;
    private String role;
    private String content;
    private List<Citation> citations;
    /**
     * Persisted self-assessment from the assistant footer. One of
     * {@code "HIGH"}, {@code "MEDIUM"}, {@code "LOW"}, or {@code null}
     * for user messages / historical rows written before the feature
     * shipped.
     */
    private String confidence;
    /**
     * Mirror of the model's {@code NEEDS_MORE_SOURCES} flag. Null for
     * user messages and pre-feature rows.
     */
    private Boolean needsMoreSources;
    /**
     * 2-3 alternative hypotheses pulled on demand by the researcher.
     * Null / empty means the user hasn't clicked "Show alternative
     * theories" on this message yet.
     */
    private List<AlternativeDTO> alternatives;
    /**
     * Consistency warnings flagged by the source cross-check. Each
     * entry names a claim on which two or more source-type classes
     * disagreed. Empty list means the check ran and found nothing;
     * null means it never ran (legacy rows).
     */
    private List<ConsistencyWarning> consistency;
    private LocalDateTime createdAt;

    public static ResearchMessageDTO from(ResearchMessage m,
                                          ThreadService threadService,
                                          AlternativesService alternativesService) {
        return ResearchMessageDTO.builder()
                .id(m.getId())
                .threadId(m.getThreadId())
                .role(m.getRole())
                .content(m.getContent())
                .citations(threadService.parseCitations(m.getCitationsJson()))
                .confidence(m.getConfidence())
                .needsMoreSources(m.getNeedsMoreSources())
                .alternatives(alternativesService.fromJson(m.getAlternativesJson())
                        .stream().map(AlternativeDTO::from).toList())
                .consistency(parseConsistency(m.getConsistencyJson()))
                .createdAt(m.getCreatedAt())
                .build();
    }

    /**
     * Decode the persisted consistency blob. Returns {@code null} if
     * the column was never written (legacy row, no check has run);
     * empty list if the check ran and found nothing; a populated list
     * otherwise. The UI relies on that {@code null} vs empty distinction
     * to decide between "no banner" and "explicit all-clear".
     */
    private static List<ConsistencyWarning> parseConsistency(String json) {
        if (json == null) return null;
        if (json.isBlank()) return Collections.emptyList();
        try {
            return CONSISTENCY_MAPPER.readerForListOf(ConsistencyWarning.class).readValue(json);
        } catch (Exception e) {
            log.debug("Could not parse consistency JSON: {}", e.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Backwards-compatible overload for callers that don't hold a
     * reference to AlternativesService - alternatives come back as
     * null. Useful for DTO tests and for endpoints that never surface
     * alternatives (e.g. the finding promote flow).
     */
    public static ResearchMessageDTO from(ResearchMessage m, ThreadService threadService) {
        return ResearchMessageDTO.builder()
                .id(m.getId())
                .threadId(m.getThreadId())
                .role(m.getRole())
                .content(m.getContent())
                .citations(threadService.parseCitations(m.getCitationsJson()))
                .confidence(m.getConfidence())
                .needsMoreSources(m.getNeedsMoreSources())
                .createdAt(m.getCreatedAt())
                .build();
    }
}
