package com.safetech.otshield.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "case_timeline_entries", indexes = {
        @Index(name = "idx_case_timeline_case_id", columnList = "case_id"),
        @Index(name = "idx_case_timeline_ts", columnList = "ts")
})
public class CaseTimelineEntry {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "case_id", nullable = false)
    private Case caseEntity;

    @Column(nullable = false)
    private LocalDateTime ts;

    @Enumerated(EnumType.STRING)
    @Column(name = "entry_type", nullable = false, length = 32)
    private CaseTimelineEntryType entryType;

    @Column(name = "actor_id", length = 128)
    private String actorId;

    @Column(name = "actor_name", length = 128)
    private String actorName;

    @Column(columnDefinition = "TEXT")
    private String content;

    /** Small key=value payload (e.g. oldStatus=NEW, newStatus=TRIAGING). JSON string. */
    @Column(name = "metadata_json", columnDefinition = "TEXT")
    private String metadataJson;

    @PrePersist
    protected void onCreate() {
        if (ts == null) ts = LocalDateTime.now();
    }
}
