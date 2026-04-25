package com.safetech.otshield.dto;

import com.safetech.otshield.model.NIS2EmailNotification;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Data Transfer Object for NIS2EmailNotification entity
 * Used for API communication between frontend and backend
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class NIS2EmailNotificationDTO {
    private String id;
    private String name;
    private String subject;
    private String body;
    private NIS2EmailNotification.NotificationType notificationType;
    private NIS2EmailNotification.NotificationStatus status;
    private Boolean isTemplate;
    private String templateId;
    private List<String> recipients;
    private List<String> ccRecipients;
    private List<String> bccRecipients;
    private String triggerCondition;
    private String scheduleCron;
    private LocalDateTime lastSentAt;
    private LocalDateTime nextSendAt;
    private Integer sentCount;
    private Integer failureCount;
    private Integer maxRetries;
    private Integer retryIntervalMinutes;
    private String customFields;
    private List<String> tags;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String createdBy;
    private String updatedBy;
} 