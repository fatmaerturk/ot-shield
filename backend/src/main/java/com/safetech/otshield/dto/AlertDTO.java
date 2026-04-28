package com.safetech.otshield.dto;

import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.AlertStatus;
import com.safetech.otshield.model.AlertType;
import lombok.Data;
import java.time.LocalDateTime;
import java.util.List;

@Data
public class AlertDTO {
    private String id;
    private String title;
    private String description;
    private AlertSeverity severity;
    private AlertStatus status;
    private AlertType type;
    private String source;
    private String sourceIp;
    private String destinationIp;
    private Integer sourcePort;
    private Integer destinationPort;
    private String protocol;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    /** Alias of {@link #createdAt} for legacy frontend code that reads
     *  `alert.timestamp` to render the detection time. Populated by the
     *  AlertMapper from createdAt so callers don't need to know which name
     *  to use. */
    private LocalDateTime timestamp;
    private LocalDateTime resolvedAt;
    private String assignedTo;
    private Boolean falsePositive;
    private Boolean acknowledged;
    private String acknowledgedBy;
    private LocalDateTime acknowledgedAt;
    private Boolean escalated;
    private List<String> tags;
    private String mitigationNotes;
    private Integer riskScore;
    private Integer confidenceScore;
} 