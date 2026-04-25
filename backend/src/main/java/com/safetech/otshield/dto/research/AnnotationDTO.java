package com.safetech.otshield.dto.research;

import com.safetech.otshield.model.research.ResearchAnnotation;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Outbound projection of a {@link ResearchAnnotation}. Enums are
 * flattened to their string names so the frontend doesn't need a
 * mirror enum definition - it just checks the string.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AnnotationDTO {
    private String id;
    private String bundleId;
    private String targetKind;
    private String targetId;
    private String kind;
    private String body;
    private String tags;
    private String author;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public static AnnotationDTO from(ResearchAnnotation a) {
        return AnnotationDTO.builder()
                .id(a.getId())
                .bundleId(a.getBundleId())
                .targetKind(a.getTargetKind() == null ? null : a.getTargetKind().name())
                .targetId(a.getTargetId())
                .kind(a.getKind() == null ? "NOTE" : a.getKind().name())
                .body(a.getBody())
                .tags(a.getTags())
                .author(a.getAuthor())
                .createdAt(a.getCreatedAt())
                .updatedAt(a.getUpdatedAt())
                .build();
    }
}
