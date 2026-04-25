package com.safetech.otshield.dto.research;

import com.safetech.otshield.model.research.VulnEvent;

import java.time.LocalDateTime;

/** One row of the observation's audit timeline. */
public record VulnEventDTO(
        String id,
        String vulnId,
        String kind,
        String fromStatus,
        String toStatus,
        String comment,
        String actor,
        LocalDateTime createdAt
) {
    public static VulnEventDTO from(VulnEvent e) {
        return new VulnEventDTO(
                e.getId(),
                e.getVulnId(),
                e.getKind() == null ? null : e.getKind().name(),
                e.getFromStatus() == null ? null : e.getFromStatus().name(),
                e.getToStatus() == null ? null : e.getToStatus().name(),
                e.getComment(),
                e.getActor(),
                e.getCreatedAt()
        );
    }
}
