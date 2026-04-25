package com.safetech.otshield.dto.research;

/**
 * Request DTOs for the Vulns REST surface. Grouped into one file so they
 * live together and are easy to scan; each is a small immutable record.
 *
 * <p>Fields are nullable on the PATCH variant so partial updates don't
 * require the client to round-trip the whole record.
 */
public final class VulnRequestDTOs {

    private VulnRequestDTOs() {}

    /**
     * Analyst-driven manual creation. All the core fields are required
     * except alternative hypotheses / CVE / CVSS / tags.
     */
    public record CreateRequest(
            String title,
            String summary,
            String componentType,
            String componentRef,
            String affectedProduct,
            String severity,
            String cveId,
            String cvssV31,
            String confidence,
            Boolean needsMoreSources,
            String alternativeHypotheses,
            String tags,
            String createdBy,
            String bundleId
    ) {}

    /**
     * Promote an assistant message into a new observation. The backend
     * copies the message text + citations verbatim; the analyst only
     * has to classify it (severity, confidence, component type).
     */
    public record PromoteRequest(
            String threadId,
            String messageId,
            String title,
            String componentType,
            String componentRef,
            String affectedProduct,
            String severity,
            String confidence,
            Boolean needsMoreSources,
            String alternativeHypotheses,
            String tags,
            String createdBy,
            String bundleId
    ) {}

    /**
     * Partial edit. Any null field is preserved from the existing row;
     * status changes always go through {@link TransitionRequest} so the
     * event log stays consistent.
     */
    public record UpdateRequest(
            String title,
            String summary,
            String componentType,
            String componentRef,
            String affectedProduct,
            String severity,
            String cveId,
            String cvssV31,
            String confidence,
            Boolean needsMoreSources,
            String mitigationSummary,
            String alternativeHypotheses,
            String tags
    ) {}

    /**
     * Status transition. Backend validates the legal transitions and
     * appends a {@code TRANSITION} row to the event log.
     */
    public record TransitionRequest(
            String toStatus,
            String comment,
            String actor
    ) {}
}
