package com.safetech.otshield.model.research;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * One-per-bundle technical summary, stored so the LLM doesn't have to
 * regenerate it on every tab open. Maps directly to the HMGCC
 * requirement: "Generate a clear technical summary of the product and
 * its individual components."
 *
 * <p>The {@code bundleId} is both the PK and the FK, enforcing the 1:1
 * relationship. The cascade delete on {@code research_bundles} disposes
 * the summary along with its owner.
 *
 * <p>{@code text} is markdown - the frontend renders it as formatted
 * content. {@code sourceDocIdsJson} records exactly which documents
 * contributed to this summary so we can show a "built from N docs"
 * footer and re-run the generator against the same inputs on demand.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "bundle_summaries")
public class BundleSummary {

    /** PK and FK - one summary per bundle. */
    @Id
    @Column(name = "bundle_id", length = 64)
    private String bundleId;

    /** Markdown-formatted summary body. */
    @Column(columnDefinition = "TEXT")
    private String text;

    /**
     * Generation lifecycle state so the async regenerate endpoint can
     * return immediately and the frontend can poll for progress:
     *
     * <ul>
     *   <li>{@code IDLE} - no generation in flight, text is authoritative</li>
     *   <li>{@code GENERATING} - background worker is running; text is stale</li>
     *   <li>{@code READY} - generator finished, text is fresh</li>
     *   <li>{@code FAILED} - generator threw; text contains the error message</li>
     * </ul>
     */
    @Column(length = 16)
    private String status;

    /** Model tag used to generate this summary (captures versioning). */
    @Column(length = 128)
    private String model;

    /** Rough token count of the prompt that produced this summary. */
    @Column(name = "prompt_tokens")
    private Integer promptTokens;

    /**
     * When the LLM generator last ran (or null if only manually authored).
     */
    @Column(name = "generated_at")
    private LocalDateTime generatedAt;

    /** When a human last edited the text. */
    @Column(name = "edited_at")
    private LocalDateTime editedAt;

    @Column(name = "edited_by", length = 128)
    private String editedBy;

    /**
     * JSON array of the source document IDs that fed the generator.
     * Lets the UI render "Built from: doc-A, doc-B, doc-C" and lets
     * the regenerate endpoint target the same scope.
     */
    @Column(name = "source_doc_ids_json", columnDefinition = "TEXT")
    private String sourceDocIdsJson;
}
