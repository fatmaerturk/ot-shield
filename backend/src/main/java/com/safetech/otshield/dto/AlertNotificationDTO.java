package com.safetech.otshield.dto;

import com.safetech.otshield.model.AlertNotification;
import lombok.Data;
import java.time.LocalDateTime;

@Data
public class AlertNotificationDTO {
    private String id;
    private String alertId;
    private AlertNotification.NotificationType notificationType;
    private String recipient;
    private String subject;
    private String message;
    private AlertNotification.NotificationStatus status;
    private LocalDateTime sentAt;
    private LocalDateTime deliveredAt;
    private LocalDateTime readAt;
    private LocalDateTime createdAt;
    private Integer retryCount;
    private Integer maxRetries;
    private String errorMessage;
    private String channelConfig;
} 