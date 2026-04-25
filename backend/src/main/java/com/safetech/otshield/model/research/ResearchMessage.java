package com.safetech.otshield.model.research;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * A single turn inside a {@link ResearchThread} - either the user's
 * question or the assistant's answer. For assistant answers we also
 * persist the JSON-serialised list of citations (passage index, source
 * file, page, snippet, score) so the UI can re-render the footer of
 * every historical answer without re-running RAG.
 *
 * <p>We deliberately keep the entire citation array as a TEXT blob
 * rather than a second table: it's always consumed as a whole, never
 * queried individually, and lives and dies with the parent message.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "research_messages", indexes = {
        @Index(name = "idx_research_messages_thread", columnList = "thread_id"),
        @Index(name = "idx_research_messages_thread_created", columnList = "thread_id, created_at")
})
public class ResearchMessage {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /** Owning thread - rows cascade-delete with the thread. */
    @Column(name = "thread_id", nullable = false, length = 64)
    private String threadId;

    /**
     * Which side of the conversation. We use a short string rather than
     * an enum so the column is easy to filter on and doesn't require
     * schema surgery when we later add {@code SYSTEM} or {@code TOOL}.
     */
    @Column(nullable = false, length = 16)
    private String role;

    /** Full text of the turn. TEXT to accommodate long RAG answers. */
    @Column(nullable = false, columnDefinition = "TEXT")
    private String content;

    /**
     * JSON array of citation objects ({@code index, source, page,
     * snippet, score}) serialized by ObjectMapper. {@code null} for
     * user messages.
     */
    @Column(name = "citations_json", columnDefinition = "TEXT")
    private String citationsJson;

    /**
     * Assistant self-assessment, stored as the string form of
     * {@code AssistantService.Confidence} ({@code HIGH} / {@code MEDIUM}
     * / {@code LOW}). Null for user messages and for historical rows
     * written before the confidence footer was introduced - the UI
     * renders those as MEDIUM by default without surfacing a pill.
     */
    @Column(name = "confidence", length = 16)
    private String confidence;

    /**
     * Mirror of the model's {@code NEEDS_MORE_SOURCES: yes|no} footer.
     * Null for user messages and historical assistant rows written
     * before the footer existed.
     */
    @Column(name = "needs_more_sources")
    private Boolean needsMoreSources;

    /**
     * JSON array of alternative hypotheses ({@code index, hypothesis,
     * rationale, confidence}) produced on demand by
     * {@code AlternativesService}. Null until the user clicks "Show
     * alternative theories" on this message; re-running the action
     * overwrites it with the latest list.
     */
    @Column(name = "alternatives_json", columnDefinition = "TEXT")
    private String alternativesJson;

    /**
     * JSON array of consistency warnings produced by
     * {@code SourceCrossCheckService} — each entry flags a claim
     * (port, password, CVE, etc.) where passages from different
     * source types gave conflicting values. Null / empty means
     * nothing was flagged; we still persist an empty array if the
     * check ran so the UI can distinguish "no conflicts" from
     * "check hasn't run yet on legacy rows".
     */
    @Column(name = "consistency_json", columnDefinition = "TEXT")
    private String consistencyJson;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;
}
