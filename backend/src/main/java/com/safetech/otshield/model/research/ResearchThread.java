package com.safetech.otshield.model.research;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * A persistent copilot conversation inside the Research Studio.
 *
 * <p>Each thread groups an ordered list of {@link ResearchMessage} rows
 * (user questions + assistant answers with their citations). Threads are
 * surfaced in the "Threads" tab of the workbench so an analyst can return
 * to a prior line of investigation without losing the retrieved sources.
 *
 * <p>The title is seeded from the first user message and can be renamed
 * later; {@code lastQuestion} is kept denormalised so the Threads list can
 * render a preview without joining the messages table.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "research_threads", indexes = {
        @Index(name = "idx_research_threads_updated_at", columnList = "updated_at")
})
public class ResearchThread {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /** Human-readable label - defaults to a slice of the first question. */
    @Column(nullable = false, length = 256)
    private String title;

    /** Preview of the most recent user question (<= 512 chars). */
    @Column(name = "last_question", length = 512)
    private String lastQuestion;

    /** Running total so the UI can show "N messages" without a join. */
    @Column(name = "message_count", nullable = false)
    private int messageCount;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    /**
     * Owning bundle (Faz 4.1). Nullable so pre-migration threads keep
     * working until the startup seeder re-homes them into Default
     * Workspace.
     */
    @Column(name = "bundle_id", length = 64)
    private String bundleId;
}
