package com.safetech.otshield.model.research;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * A single retrievable slice of a {@link ResearchDocument}. Each chunk
 * carries the raw text (so we can show it verbatim in the UI alongside
 * a cited answer) plus the embedding vector as a byte blob.
 *
 * <p>The vector is stored as a {@code float[]} serialised into a byte
 * array rather than using PostgreSQL's {@code pgvector} type, because
 * pgvector isn't available on the user's PG 18 install yet. This row is
 * really the source of truth we hydrate into the in-memory vector store
 * on startup - nearest-neighbour search never touches SQL.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "research_document_chunks", indexes = {
        @Index(name = "idx_chunks_document", columnList = "document_id"),
        @Index(name = "idx_chunks_ordinal", columnList = "document_id,ordinal")
})
public class ResearchDocumentChunk {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /** Parent document id. Foreign key without JPA relationship to keep queries fast. */
    @Column(name = "document_id", nullable = false, length = 64)
    private String documentId;

    /** Zero-based position within the parent document, in reading order. */
    @Column(nullable = false)
    private int ordinal;

    /** 1-based page number for PDFs; {@code null} otherwise. */
    @Column(name = "page_number")
    private Integer pageNumber;

    /** Raw chunk text. TEXT column - no length cap - so long passages survive. */
    @Column(columnDefinition = "TEXT", nullable = false)
    private String text;

    /**
     * Embedding vector, serialised as little-endian float32 bytes.
     * nomic-embed-text emits 768-dim vectors so this is typically 3072 bytes.
     *
     * <p><b>Important:</b> do not annotate this field with {@code @Lob}.
     * Hibernate interprets {@code @Lob} on a {@code byte[]} against
     * PostgreSQL as "use Large Objects" and binds a {@code BIGINT} OID
     * instead of the bytes, which blows up against a {@code BYTEA}
     * column with "column \"embedding\" is of type bytea but expression
     * is of type bigint". The column definition below binds straight to
     * {@code BYTEA} and Hibernate maps {@code byte[]} to it natively.
     */
    @Column(name = "embedding", nullable = false, columnDefinition = "BYTEA")
    private byte[] embedding;

    /** Convenience denormalisation - the original file name, used as citation label. */
    @Column(name = "source_label", nullable = false, length = 512)
    private String sourceLabel;
}
