package com.safetech.otshield.dto.research;

/** Request DTOs for the bundle REST surface. Patch-friendly: null = leave as-is. */
public final class BundleRequestDTOs {
    private BundleRequestDTOs() {}

    public record CreateRequest(
            String name,
            String slug,
            String tags,
            String description,
            String watchFolderPath,
            Boolean watchEnabled
    ) {}

    public record UpdateRequest(
            String name,
            String slug,
            String tags,
            String description,
            String watchFolderPath,
            Boolean watchEnabled
    ) {}
}
