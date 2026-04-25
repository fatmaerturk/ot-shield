package com.safetech.otshield.dto.research;

import com.safetech.otshield.model.research.InventoryItem;

import java.time.LocalDateTime;

public record InventoryItemDTO(
        String id,
        String bundleId,
        String kind,
        String name,
        String details,
        String reference,
        String source,
        String tags,
        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
    public static InventoryItemDTO from(InventoryItem i) {
        return new InventoryItemDTO(
                i.getId(),
                i.getBundleId(),
                i.getKind() == null ? null : i.getKind().name(),
                i.getName(),
                i.getDetails(),
                i.getReference(),
                i.getSource(),
                i.getTags(),
                i.getCreatedAt(),
                i.getUpdatedAt()
        );
    }
}
