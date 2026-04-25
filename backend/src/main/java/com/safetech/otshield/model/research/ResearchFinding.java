package com.safetech.otshield.model.research;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * An analyst-approved answer promoted out of a conversation into the
 * permanent evidence ledger ("Findings" tab). Unlike raw messages,
 * findings are curated: they can be edited, tagged, and surfaced as
 * reusable knowledge.
 *
 * <p>The citations are copied verbatim from the originating message so
 * the finding remains valid even if the source thread is later deleted.
 * {@code sourceThreadId} / {@code sourceMessageId} are kept for
 * provenance but are not foreign keys - deleting the thread must not
 * cascade into an approved finding.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "research_findings", indexes = {
        @Index(name = "idx_research_findings_created_at", columnList = "created_at")
})
public class ResearchFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /** Short human title - defaults to a slice of the first sentence. */
    @Column(nullable = false, length = 256)
    private String title;

    /**
     * Full body of the finding. Starts as a copy of the promoted
     * message content but can be edited by the analyst.
     */
    @Column(nullable = false, columnDefinition = "TEXT")
    private String text;

    /** JSON array of citation objects, copied from the source message. */
    @Column(name = "citations_json", columnDefinition = "TEXT")
    private String citationsJson;

    /** Optional provenance - thread this was promoted from. */
    @Column(name = "source_thread_id", length = 64)
    private String sourceThreadId;

    /** Optional provenance - message this was promoted from. */
    @Column(name = "source_message_id", length = 64)
    private String sourceMessageId;

    /** Comma-separated free-form tags (e.g. "plc,siemens,s7-1500"). */
    @Column(length = 512)
    private String tags;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    /** Owning bundle (Faz 4.1). Nullable pre-migration. */
    @Column(name = "bundle_id", length = 64)
    private String bundleId;
}
