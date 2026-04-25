package com.safetech.otshield.dto.research;

import com.safetech.otshield.model.research.ResearchBundle;

import java.time.LocalDateTime;

/**
 * Projection for the Research bundle sidebar. Includes roll-up counters
 * so the sidebar can show "3 docs · 2 threads · 5 vulns" next to the
 * bundle name without a second round-trip.
 */
public record BundleDTO(
        String id,
        String name,
        String slug,
        String tags,
        String description,
        String watchFolderPath,
        boolean watchEnabled,
        LocalDateTime createdAt,
        LocalDateTime updatedAt,
        long documentCount,
        long threadCount,
        long findingCount,
        long vulnCount
) {
    public static BundleDTO from(ResearchBundle b,
                                 long documentCount,
                                 long threadCount,
                                 long findingCount,
                                 long vulnCount) {
        return new BundleDTO(
                b.getId(),
                b.getName(),
                b.getSlug(),
                b.getTags(),
                b.getDescription(),
                b.getWatchFolderPath(),
                b.isWatchEnabled(),
                b.getCreatedAt(),
                b.getUpdatedAt(),
                documentCount,
                threadCount,
                findingCount,
                vulnCount
        );
    }
}
