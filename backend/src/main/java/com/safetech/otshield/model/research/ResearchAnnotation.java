package com.safetech.otshield.model.research;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Sticky-note / flag annotation a researcher attaches to something
 * they looked at — an assistant answer, a single citation, or a
 * library document. Covers the HMGCC "researcher workflow"
 * requirement without forcing full PDF-highlight ergonomics.
 *
 * <p>The entity is deliberately polymorphic via a string
 * {@code target_kind} + {@code target_id} pair instead of a forest
 * of nullable FKs. This keeps the schema tight and the UI can still
 * filter / group exactly the way it needs (e.g. "all notes on this
 * thread message", "all red flags in this bundle").
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "research_annotations", indexes = {
        @Index(name = "idx_research_annotations_bundle", columnList = "bundle_id"),
        @Index(name = "idx_research_annotations_target", columnList = "target_kind, target_id"),
        @Index(name = "idx_research_annotations_created", columnList = "created_at")
})
public class ResearchAnnotation {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /**
     * Owning bundle. Nullable so pre-migration rows coexist with the
     * "Default Workspace" seeder; brand-new annotations always carry
     * a bundle id.
     */
    @Column(name = "bundle_id", length = 64)
    private String bundleId;

    /**
     * What this annotation is attached to. See {@link TargetKind}.
     * Stored as a short string so new kinds (e.g. inventory item) can
     * be added without a schema migration.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "target_kind", nullable = false, length = 32)
    private TargetKind targetKind;

    /**
     * The id of the target object. For MESSAGE it's a
     * {@code research_messages.id}; for DOCUMENT a
     * {@code research_documents.id}; for CITATION we compose
     * {@code messageId + "#" + citationIndex}; for FREEFORM it's
     * the bundle id (the note is just pinned to the bundle).
     */
    @Column(name = "target_id", nullable = false, length = 128)
    private String targetId;

    /**
     * Semantic flavour of the note. Drives the UI colour +
     * filtering, nothing more. Using a string column keeps additions
     * cheap.
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private Kind kind;

    /** The note body itself. TEXT because researchers write essays. */
    @Column(nullable = false, columnDefinition = "TEXT")
    private String body;

    /** Freeform tags, comma-separated. Optional. */
    @Column(length = 256)
    private String tags;

    /**
     * Username of the author (pulled from the JWT / localStorage on
     * the client side). Null for rows written before the user system
     * was introduced.
     */
    @Column(name = "author", length = 128)
    private String author;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    public enum TargetKind {
        /** Attached to a thread message id. */
        MESSAGE,
        /** Attached to a library document id. */
        DOCUMENT,
        /** Attached to a citation within an assistant message. */
        CITATION,
        /** Free-form note pinned to the bundle itself. */
        FREEFORM
    }

    public enum Kind {
        /** Neutral note. Default. */
        NOTE,
        /** Yellow highlighter — "read this again". */
        HIGHLIGHT,
        /** Red flag — "this looks wrong / suspicious". */
        FLAG,
        /** Green tick — "verified, trust this". */
        VERIFIED
    }
}
