package com.safetech.otshield.model.research;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * A Bundle is a scoped workspace inside Research Studio - one self-contained
 * investigation with its own documents, threads, findings, vulnerability
 * observations, inventory, summary, and optional watch folder. Every
 * downstream entity carries a {@code bundle_id} so the same OTShield
 * install can host many parallel researches without their context
 * bleeding into each other.
 *
 * <p>HMGCC call alignment: "Keep a memory of queries so conversations can
 * be continued over several weeks without repetition of prompts." - a
 * bundle is the serialisation unit of that memory, including the watch
 * folder and snapshot export path that let a researcher round-trip an
 * investigation across air-gapped machines.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "research_bundles", indexes = {
        @Index(name = "idx_bundles_slug",       columnList = "slug", unique = true),
        @Index(name = "idx_bundles_updated_at", columnList = "updated_at")
})
public class ResearchBundle {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /** Human-visible name, shown in the sidebar ("Siemens S7-1500 teardown"). */
    @Column(nullable = false, length = 256)
    private String name;

    /**
     * URL-safe slug derived from the name. Lets us deep-link to a bundle
     * ({@code /research/library?bundle=siemens-s7-1500}) without exposing
     * UUIDs in the URL bar. Unique across all bundles.
     */
    @Column(nullable = false, length = 128, unique = true)
    private String slug;

    /** Free-text comma-separated tags, rendered as pills under the name. */
    @Column(length = 512)
    private String tags;

    /**
     * Server-side absolute path of a watch folder. When
     * {@link #watchEnabled} is true the ingest poller copies any new
     * files dropped into this folder into the Library and deletes the
     * source. Per HMGCC "must work without internet" constraint, this
     * is the air-gapped hand-off mechanism.
     */
    @Column(name = "watch_folder_path", length = 1024)
    private String watchFolderPath;

    /** Feature flag for the watch poller. Default off so nothing runs by surprise. */
    @Column(name = "watch_enabled", nullable = false)
    private boolean watchEnabled;

    /**
     * Optional one-line description shown under the bundle title. Lets
     * researchers leave themselves a note about the scope or target.
     */
    @Column(length = 512)
    private String description;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;
}
