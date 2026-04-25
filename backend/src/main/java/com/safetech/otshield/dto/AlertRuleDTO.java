package com.safetech.otshield.dto;

import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.AlertType;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.List;

@Data
public class AlertRuleDTO {
    private String id;
    private String name;
    private String description;
    private AlertSeverity severity;
    private AlertType type;
    private Boolean enabled;
    private String condition;
    private String action;
    private Integer thresholdValue;
    private Integer timeWindowMinutes;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String createdBy;
    private String updatedBy;
    private List<String> tags;
    private Integer priority;
    private String category;
    private String sourceSystems;
    private Boolean suppressionEnabled;
    private Integer suppressionDurationMinutes;
    private String notificationChannels;
} 