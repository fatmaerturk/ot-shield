package com.safetech.otshield.model.research;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Append-only audit entry for a {@link VulnObservation}.
 *
 * <p>HMGCC call: "Have an ability to check and validate responses before
 * publishing, to prevent erroneous information and hallucinations." The
 * only way to make that meaningful is to preserve <em>why</em> an
 * observation reached its current state - which researcher verified it,
 * what the reviewer said, when it was mitigated. We never update or
 * delete these rows; they are the provenance for any downstream report.
 *
 * <p>The {@code kind} captures the flavour of event so the detail drawer
 * timeline can render richer content than just "status changed":
 * transitions, edits, comments, and the original promote all live in
 * this table.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "vuln_events", indexes = {
        @Index(name = "idx_vuln_events_vuln",    columnList = "vuln_id"),
        @Index(name = "idx_vuln_events_created", columnList = "vuln_id,created_at")
})
public class VulnEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(name = "vuln_id", nullable = false, length = 64)
    private String vulnId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private EventKind kind;

    /** For TRANSITION events, the status <em>before</em> the change. */
    @Enumerated(EnumType.STRING)
    @Column(name = "from_status", length = 24)
    private VulnObservation.VulnStatus fromStatus;

    /** For TRANSITION events, the status <em>after</em> the change. */
    @Enumerated(EnumType.STRING)
    @Column(name = "to_status", length = 24)
    private VulnObservation.VulnStatus toStatus;

    /** Free-text comment the researcher attached to this event. */
    @Column(columnDefinition = "TEXT")
    private String comment;

    /** Whoever triggered the event. Plain name for now (no multi-user). */
    @Column(length = 128)
    private String actor;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    public enum EventKind {
        CREATED,
        PROMOTED,
        TRANSITION,
        EDITED,
        COMMENT
    }
}
