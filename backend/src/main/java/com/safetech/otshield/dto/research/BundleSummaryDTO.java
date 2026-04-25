package com.safetech.otshield.dto.research;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.safetech.otshield.model.research.BundleSummary;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.List;

/**
 * Wire shape for the Summary tab. {@code sourceDocIds} is returned as a
 * real list so the frontend doesn't have to re-parse the stored JSON.
 */
public record BundleSummaryDTO(
        String bundleId,
        String text,
        String model,
        Integer promptTokens,
        LocalDateTime generatedAt,
        LocalDateTime editedAt,
        String editedBy,
        List<String> sourceDocIds,
        String status
) {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static BundleSummaryDTO from(BundleSummary s) {
        return new BundleSummaryDTO(
                s.getBundleId(),
                s.getText(),
                s.getModel(),
                s.getPromptTokens(),
                s.getGeneratedAt(),
                s.getEditedAt(),
                s.getEditedBy(),
                parseDocIds(s.getSourceDocIdsJson()),
                s.getStatus() == null ? "IDLE" : s.getStatus()
        );
    }

    private static List<String> parseDocIds(String json) {
        if (json == null || json.isBlank()) return Collections.emptyList();
        try {
            return MAPPER.readValue(json, new TypeReference<List<String>>() {});
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }
}
