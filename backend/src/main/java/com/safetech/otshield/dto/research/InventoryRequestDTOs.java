package com.safetech.otshield.dto.research;

/** Inventory create/update request bodies. Patch-friendly. */
public final class InventoryRequestDTOs {
    private InventoryRequestDTOs() {}

    public record CreateRequest(
            String kind,
            String name,
            String details,
            String reference,
            String source,
            String tags
    ) {}

    public record UpdateRequest(
            String kind,
            String name,
            String details,
            String reference,
            String source,
            String tags
    ) {}
}
