package com.safetech.otshield.dto.research;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.safetech.otshield.model.research.VulnObservation;
import com.safetech.otshield.service.assistant.AssistantService.Citation;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

/**
 * Projection for {@link VulnObservation} returned to the frontend.
 *
 * <p>{@code citationsJson} is parsed into a real {@link Citation} list
 * here so the UI doesn't have to double-decode. Failed parses fall
 * through to an empty list - citations are a nice-to-have, not a hard
 * contract.
 */
public record VulnObservationDTO(
        String id,
        String title,
        String summary,
        String componentType,
        String componentRef,
        String affectedProduct,
        String severity,
        String cveId,
        String cvssV31,
        String confidence,
        boolean needsMoreSources,
        String status,
        String mitigationSummary,
        String sourceThreadId,
        String sourceMessageId,
        List<Citation> citations,
        String alternativeHypotheses,
        String tags,
        LocalDateTime createdAt,
        LocalDateTime updatedAt,
        String createdBy,
        String verifiedBy
) {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static VulnObservationDTO from(VulnObservation v) {
        return new VulnObservationDTO(
                v.getId(),
                v.getTitle(),
                v.getSummary(),
                v.getComponentType() == null ? null : v.getComponentType().name(),
                v.getComponentRef(),
                v.getAffectedProduct(),
                v.getSeverity() == null ? null : v.getSeverity().name(),
                v.getCveId(),
                v.getCvssV31(),
                v.getConfidence() == null ? null : v.getConfidence().name(),
                v.isNeedsMoreSources(),
                v.getStatus() == null ? null : v.getStatus().name(),
                v.getMitigationSummary(),
                v.getSourceThreadId(),
                v.getSourceMessageId(),
                parseCitations(v.getCitationsJson()),
                v.getAlternativeHypotheses(),
                v.getTags(),
                v.getCreatedAt(),
                v.getUpdatedAt(),
                v.getCreatedBy(),
                v.getVerifiedBy()
        );
    }

    private static List<Citation> parseCitations(String json) {
        if (json == null || json.isBlank()) return Collections.emptyList();
        try {
            return MAPPER.readValue(json, new TypeReference<List<Citation>>() {});
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }
}
