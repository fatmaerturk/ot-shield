package com.safetech.otshield.dto;

import com.safetech.otshield.mapper.AlertEscalation;
import lombok.Data;
import java.time.LocalDateTime;

@Data
public class AlertEscalationDTO {
    private String id;
    private String alertId;
    private Integer escalationLevel;
    private String escalatedFrom;
    private String escalatedTo;
    private String escalationReason;
    private LocalDateTime escalationTime;
    private LocalDateTime responseTime;
    private LocalDateTime resolutionTime;
    private AlertEscalation.EscalationStatus status;
    private Integer timeoutMinutes;
    private Boolean autoEscalate;
    private String escalationPolicy;
    private String notes;
} 