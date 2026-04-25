package com.safetech.otshield.dto;

import com.safetech.otshield.mapper.AlertComment;
import lombok.Data;
import java.time.LocalDateTime;

@Data
public class AlertCommentDTO {
    private String id;
    private String alertId;
    private String commentText;
    private String createdBy;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private Boolean isInternal;
    private AlertComment.CommentType commentType;
    private String attachments;
} 