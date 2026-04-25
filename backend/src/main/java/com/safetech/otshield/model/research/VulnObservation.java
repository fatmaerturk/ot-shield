package com.safetech.otshield.model.research;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Research-driven vulnerability observation.
 *
 * <p>This is not a CVE tracker - it is a <em>researcher-authored hypothesis
 * ledger</em> aligned with HMGCC Co-Creation's essential requirements:
 *
 * <ul>
 *   <li>"Have an ability to check and validate responses before publishing,
 *       to prevent erroneous information and hallucinations"
 *       &rarr; explicit {@link VulnStatus} lifecycle
 *       ({@code DRAFT} &rarr; {@code UNDER_REVIEW} &rarr; {@code VERIFIED}
 *       &rarr; {@code MITIGATED}, with {@code DISMISSED} / {@code FALSE_POSITIVE}
 *       as terminal off-ramps)</li>
 *   <li>"Flag a confidence score and if more source data is required"
 *       &rarr; {@link VulnConfidence} + {@code needsMoreSources} boolean</li>
 *   <li>"Verify information by listing sources" &rarr; {@code citationsJson}
 *       copied from the originating assistant message</li>
 *   <li>"Where answers are not clear, this is highlighted with alternative
 *       theories" &rarr; {@code alternativeHypotheses} TEXT field</li>
 *   <li>"Keep a memory of queries so conversations can be continued"
 *       &rarr; {@code sourceThreadId} + {@code sourceMessageId} so the
 *       researcher can jump back to the conversation that produced this
 *       observation weeks later</li>
 *   <li>"Must work without an internet connection" &rarr; no CVE/NVD
 *       lookup; {@code cveId} and {@code cvssV31} are free-text fields
 *       the researcher enters manually</li>
 * </ul>
 *
 * <p>Append-only state transitions are recorded in {@link VulnEvent}
 * so the audit trail survives edits.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "vulnerability_observations", indexes = {
        @Index(name = "idx_vulns_status",   columnList = "status"),
        @Index(name = "idx_vulns_severity", columnList = "severity"),
        @Index(name = "idx_vulns_updated",  columnList = "updated_at"),
        @Index(name = "idx_vulns_needs_sources", columnList = "needs_more_sources")
})
public class VulnObservation {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    // ---- Core identity --------------------------------------------------

    @Column(nullable = false, length = 256)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String summary;

    /** What kind of thing is this observation about. Drives the UI icon and filter. */
    @Enumerated(EnumType.STRING)
    @Column(name = "component_type", nullable = false, length = 32)
    private ComponentType componentType;

    /** Free-text pointer to the specific interface/part ("Port 23 on mgmt NIC"). */
    @Column(name = "component_ref", length = 512)
    private String componentRef;

    /** Optional link to an uploaded document's productLabel. */
    @Column(name = "affected_product", length = 256)
    private String affectedProduct;

    // ---- Risk + confidence ---------------------------------------------

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private VulnSeverity severity;

    /**
     * Free-text CVE identifier ({@code CVE-2024-1234}) or internal ref.
     * No online lookup - offline-first per HMGCC constraint.
     */
    @Column(name = "cve_id", length = 64)
    private String cveId;

    /** Free-text CVSS v3.1 vector string or score. Also manual, no feed. */
    @Column(name = "cvss_v31", length = 128)
    private String cvssV31;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private VulnConfidence confidence;

    /**
     * Researcher flag: "I'm not done yet, I need more sources before this
     * can be verified". Drives the Vulns tab KPI "Needs more sources".
     */
    @Column(name = "needs_more_sources", nullable = false)
    private boolean needsMoreSources;

    // ---- Lifecycle ------------------------------------------------------

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 24)
    private VulnStatus status;

    /** Filled in when the observation reaches {@code MITIGATED}. */
    @Column(name = "mitigation_summary", columnDefinition = "TEXT")
    private String mitigationSummary;

    // ---- Provenance + alternative theories ------------------------------

    /** Nullable - null when the analyst created this manually. */
    @Column(name = "source_thread_id", length = 64)
    private String sourceThreadId;

    /** Nullable - null when manually authored or the message was deleted. */
    @Column(name = "source_message_id", length = 64)
    private String sourceMessageId;

    /**
     * Citations copied verbatim from the originating assistant message at
     * promote-time. Stored as JSON so the observation stays self-contained
     * even if the source message is deleted later.
     */
    @Column(name = "citations_json", columnDefinition = "TEXT")
    private String citationsJson;

    /**
     * Markdown-formatted alternative hypotheses. HMGCC call: "Where answers
     * are not clear, this is highlighted with alternative theories."
     */
    @Column(name = "alternative_hypotheses", columnDefinition = "TEXT")
    private String alternativeHypotheses;

    /** Comma-separated tags for analyst-driven organisation. */
    @Column(length = 512)
    private String tags;

    // ---- Audit ---------------------------------------------------------

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    /** Analyst name / email. Free-text for now - we don't have multi-user yet. */
    @Column(name = "created_by", length = 128)
    private String createdBy;

    /** Filled in on the {@code UNDER_REVIEW -> VERIFIED} transition. */
    @Column(name = "verified_by", length = 128)
    private String verifiedBy;

    /**
     * Owning bundle (Faz 4.1). Nullable so pre-migration observations
     * work until the startup seeder re-homes them.
     */
    @Column(name = "bundle_id", length = 64)
    private String bundleId;

    // ---- Enums ---------------------------------------------------------

    public enum ComponentType {
        PROTOCOL,
        INTERFACE,
        FIRMWARE,
        SOFTWARE,
        HARDWARE_COMPONENT,
        CONFIGURATION,
        SUPPLY_CHAIN,
        OTHER
    }

    public enum VulnSeverity {
        CRITICAL,
        HIGH,
        MEDIUM,
        LOW,
        INFO
    }

    public enum VulnConfidence {
        HIGH,
        MEDIUM,
        LOW
    }

    /**
     * Lifecycle for hallucination-prevention. Every promoted or manually
     * created observation starts as {@code DRAFT} and must pass through
     * {@code UNDER_REVIEW} and be explicitly {@code VERIFIED} before any
     * downstream report can treat it as ground truth.
     *
     * <p>{@code DISMISSED} is "not a real vulnerability, but worth keeping
     * in the record"; {@code FALSE_POSITIVE} is "this was produced by the
     * RAG layer and the researcher rejected it" - we distinguish because
     * FP rate feeds back into retrieval tuning.
     */
    public enum VulnStatus {
        DRAFT,
        UNDER_REVIEW,
        VERIFIED,
        MITIGATED,
        DISMISSED,
        FALSE_POSITIVE
    }
}
