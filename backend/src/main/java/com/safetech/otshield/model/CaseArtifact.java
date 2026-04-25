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
@Table(name = "case_artifacts", indexes = {
        @Index(name = "idx_case_artifacts_case_id", columnList = "case_id"),
        @Index(name = "idx_case_artifacts_type", columnList = "artifact_type"),
        @Index(name = "idx_case_artifacts_value", columnList = "value")
})
public class CaseArtifact {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @JsonIgnore
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "case_id", nullable = false)
    private Case caseEntity;

    @Enumerated(EnumType.STRING)
    @Column(name = "artifact_type", nullable = false, length = 32)
    private CaseArtifactType artifactType;

    @Column(nullable = false, length = 512)
    private String value;

    @Column(length = 256)
    private String label;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "added_by", length = 128)
    private String addedBy;

    @Column(name = "added_at", nullable = false)
    private LocalDateTime addedAt;

    @Column(name = "malicious")
    private Boolean malicious;

    @PrePersist
    protected void onCreate() {
        if (addedAt == null) addedAt = LocalDateTime.now();
        if (malicious == null) malicious = Boolean.TRUE;
    }
}
