package com.safetech.otshield.dto;

import com.safetech.otshield.model.Anomaly;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AnomalyDTO {
    private String id;
    private String title;
    private String description;
    private Anomaly.AnomalyType anomalyType;
    private Anomaly.AnomalySeverity severity;
    private Anomaly.AnomalyStatus status;
    private String sourceIp;
    private String destinationIp;
    private Integer sourcePort;
    private Integer destinationPort;
    private String protocol;
    private String assetType;
    private String assetCategory;
    private String purdueLevel;
    private String manufacturer;
    private String model;
    private String hostname;
    private String location;
    private String department;
    private String evidence;
    private String mitigationSteps;
    private String recommendations;
    private Double confidenceScore;
    private Double riskScore;
    private Integer falsePositiveProbability;
    private String mitreTactic;
    private String mitreTechnique;
    private String mitreId;
    private List<String> tags;
    private List<String> indicators;
    private String customFields;
    private LocalDateTime detectedAt;
    private LocalDateTime resolvedAt;
    private LocalDateTime acknowledgedAt;
    private LocalDateTime escalatedAt;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String createdBy;
    private String updatedBy;
    private String assignedTo;
    private String resolvedBy;
    private String notes;
    private Boolean isActive;
    private Boolean isEscalated;
    private Boolean isAcknowledged;
    private Boolean isResolved;
    private Boolean isFalsePositive;
} 