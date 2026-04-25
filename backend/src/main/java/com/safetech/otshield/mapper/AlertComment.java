package com.safetech.otshield.mapper;

import com.safetech.otshield.model.Alert;
import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "alert_comments")
public class AlertComment {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "alert_id", nullable = false)
    private Alert alert;

    @Column(name = "comment_text", columnDefinition = "TEXT", nullable = false)
    private String commentText;

    @Column(name = "created_by", nullable = false)
    private String createdBy;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "is_internal")
    private Boolean isInternal = false;

    @Column(name = "comment_type")
    @Enumerated(EnumType.STRING)
    private CommentType commentType = CommentType.GENERAL;

    @Column(name = "attachments")
    private String attachments;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    public enum CommentType {
        GENERAL("General"),
        INVESTIGATION("Investigation"),
        MITIGATION("Mitigation"),
        ESCALATION("Escalation"),
        RESOLUTION("Resolution"),
        INTERNAL_NOTE("Internal Note");

        private final String displayName;

        CommentType(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }

        @Override
        public String toString() {
            return displayName;
        }
    }
} 