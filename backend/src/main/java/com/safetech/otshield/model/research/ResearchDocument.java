package com.safetech.otshield.model.research;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * One piece of reference material uploaded into the Research Studio
 * library - a manual, datasheet, forum dump, schematic PDF, etc. The raw
 * file bytes are written to disk under the upload directory; this row
 * only carries metadata plus a reference to the stored path so we don't
 * bloat the database with binary blobs.
 *
 * <p>Each document fans out into many {@link ResearchDocumentChunk} rows
 * during ingest. Chunks are what the vector store and the assistant's
 * RAG retrieval layer actually see; the document row itself is only
 * shown in the Library UI.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "research_documents", indexes = {
        @Index(name = "idx_research_docs_status", columnList = "status"),
        @Index(name = "idx_research_docs_uploaded_at", columnList = "uploaded_at")
})
public class ResearchDocument {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /** Original file name as uploaded. Used as the citation label. */
    @Column(name = "file_name", nullable = false, length = 512)
    private String fileName;

    /** File size in bytes - surfaced in the Library list. */
    @Column(name = "size_bytes", nullable = false)
    private long sizeBytes;

    /**
     * Detected MIME type (e.g. {@code application/pdf}). Drives which
     * extractor strategy runs during ingest.
     */
    @Column(name = "content_type", length = 128)
    private String contentType;

    /** Absolute path to the stored binary on disk. */
    @Column(name = "storage_path", nullable = false, length = 1024)
    private String storagePath;

    /**
     * Optional user-provided product/project label so the Library can
     * group documents by machine. Free-form text for now; we'll promote
     * to a proper entity once the UI needs it.
     */
    @Column(name = "product_label", length = 256)
    private String productLabel;

    /** Number of pages (for PDFs) or {@code null} for other formats. */
    @Column(name = "page_count")
    private Integer pageCount;

    /** Total chunk count generated from this document. */
    @Column(name = "chunk_count", nullable = false)
    private int chunkCount;

    /**
     * Current processing state. Exposed to the UI so the user sees
     * why a freshly uploaded file can't be queried yet.
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private IngestStatus status;

    /** Populated when {@link #status} is {@code FAILED}. */
    @Column(name = "error_message", length = 2048)
    private String errorMessage;

    @Column(name = "uploaded_at", nullable = false)
    private LocalDateTime uploadedAt;

    @Column(name = "ingested_at")
    private LocalDateTime ingestedAt;

    /**
     * Owning bundle (Faz 4.1). Nullable so pre-migration rows coexist
     * until the startup seeder re-homes them into "Default Workspace".
     */
    @Column(name = "bundle_id", length = 64)
    private String bundleId;

    /**
     * Source-type taxonomy used by the HMGCC "source cross-check"
     * requirement. A vendor manual carries more weight than a forum
     * post, so we stamp every document with a class that the citation
     * pill surfaces inline and a future cross-check service can use to
     * detect contradictions across types.
     *
     * <p>Heuristic classification runs on upload; users can override it
     * from the Library row if the guess is wrong.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "source_type", length = 32)
    private SourceType sourceType;

    public enum IngestStatus {
        /** Just landed on disk - extraction has not run yet. */
        UPLOADED,
        /** Extractor + embedder in flight. */
        PROCESSING,
        /** Chunks are embedded and present in the vector store. */
        READY,
        /** Ingest failed; {@link #errorMessage} explains why. */
        FAILED
    }

    /**
     * Source taxonomy surfaced to citation pills and the cross-check
     * layer. {@code UNKNOWN} is the conservative default when none of
     * the heuristics fire - the user can still reassign it manually.
     */
    public enum SourceType {
        /**
         * Official vendor-published operator, installation, or service
         * manual. The highest-trust class.
         */
        VENDOR_MANUAL,
        /**
         * Short-form product spec sheet (pin-outs, register maps,
         * electrical characteristics). High trust, narrow scope.
         */
        DATASHEET,
        /**
         * Community forum thread, mailing list archive, StackExchange
         * answer. Low trust, often useful context.
         */
        FORUM,
        /**
         * Peer-reviewed paper, conference proceedings, academic
         * thesis. Medium-high trust; frequently out of date for the
         * specific firmware the researcher is tearing down.
         */
        ACADEMIC,
        /**
         * Raw source code, firmware dump text, configuration file.
         * Treated separately because grep'ing a binary string is a
         * different mental model than reading a manual.
         */
        CODE,
        /** Nothing matched - treat as "citation only, verify carefully". */
        UNKNOWN
    }
}
