package com.safetech.otshield.model.research;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * One-per-bundle status row for long-running inventory extractions.
 *
 * <p>The regex extractor is synchronous and doesn't need this - it
 * returns its result in the response. The LLM "deep extract" path is
 * the opposite: it can easily take a minute or more on CPU-only
 * hosts, and we don't want to hold the HTTP connection open. So we
 * follow the Summary tab's pattern: flip this row to
 * {@code GENERATING}, fire off a background worker, let the frontend
 * poll.
 *
 * <p>{@code bundleId} is both the PK and the FK, giving us a
 * one-job-per-bundle model. Running a second extract while one is in
 * flight is a no-op (service checks status).
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "inventory_extraction_jobs")
public class ExtractionJob {

    @Id
    @Column(name = "bundle_id", length = 64)
    private String bundleId;

    /** IDLE, GENERATING, READY, FAILED. */
    @Column(length = 16)
    private String status;

    /** Free-text message - error text or a "created N items" summary. */
    @Column(length = 1024)
    private String message;

    /** Running count the background worker writes so the UI can show progress. */
    @Column(name = "items_created")
    private Integer itemsCreated;

    @Column(name = "started_at")
    private LocalDateTime startedAt;

    @Column(name = "finished_at")
    private LocalDateTime finishedAt;
}
