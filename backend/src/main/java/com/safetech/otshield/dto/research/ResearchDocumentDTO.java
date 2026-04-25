package com.safetech.otshield.dto.research;

import com.safetech.otshield.model.research.ResearchDocument;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Outbound projection of a {@link ResearchDocument} row. Strips the
 * internal storage path (leaking absolute OS paths to the browser is
 * both useless and mildly hostile) and pins the enum onto a plain
 * string so the UI doesn't need to import Jakarta enum constants.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ResearchDocumentDTO {
    private String id;
    private String fileName;
    private long sizeBytes;
    private String contentType;
    private String productLabel;
    private Integer pageCount;
    private int chunkCount;
    private String status;
    private String errorMessage;
    private LocalDateTime uploadedAt;
    private LocalDateTime ingestedAt;
    /**
     * Document class (VENDOR_MANUAL, DATASHEET, FORUM, ACADEMIC, CODE,
     * UNKNOWN). Stamped by the heuristic classifier on ingest; the
     * user can reassign from the Library row.
     */
    private String sourceType;

    public static ResearchDocumentDTO from(ResearchDocument d) {
        return ResearchDocumentDTO.builder()
                .id(d.getId())
                .fileName(d.getFileName())
                .sizeBytes(d.getSizeBytes())
                .contentType(d.getContentType())
                .productLabel(d.getProductLabel())
                .pageCount(d.getPageCount())
                .chunkCount(d.getChunkCount())
                .status(d.getStatus() == null ? null : d.getStatus().name())
                .errorMessage(d.getErrorMessage())
                .uploadedAt(d.getUploadedAt())
                .ingestedAt(d.getIngestedAt())
                .sourceType(d.getSourceType() == null
                        ? ResearchDocument.SourceType.UNKNOWN.name()
                        : d.getSourceType().name())
                .build();
    }
}
