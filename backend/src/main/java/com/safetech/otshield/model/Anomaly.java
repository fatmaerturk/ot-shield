package com.safetech.otshield.model;

import jakarta.persistence.*;
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
@Entity
@Table(name = "anomalies")
public class Anomaly {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false)
    private String title;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AnomalyType anomalyType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AnomalySeverity severity;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AnomalyStatus status;

    @Column(nullable = false)
    private String sourceIp;

    @Column(nullable = false)
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

    @Column(columnDefinition = "TEXT")
    private String evidence;

    @Column(columnDefinition = "TEXT")
    private String mitigationSteps;

    @Column(columnDefinition = "TEXT")
    private String recommendations;

    private Double confidenceScore;
    private Double riskScore;
    private Integer falsePositiveProbability;
    private String mitreTactic;
    private String mitreTechnique;
    private String mitreId;

    @ElementCollection
    @CollectionTable(name = "anomaly_tags", joinColumns = @JoinColumn(name = "anomaly_id"))
    @Column(name = "tag")
    private List<String> tags;

    @ElementCollection
    @CollectionTable(name = "anomaly_indicators", joinColumns = @JoinColumn(name = "anomaly_id"))
    @Column(name = "indicator")
    private List<String> indicators;

    @Column(columnDefinition = "TEXT")
    private String customFields;

    private LocalDateTime detectedAt;
    private LocalDateTime resolvedAt;
    private LocalDateTime acknowledgedAt;
    private LocalDateTime escalatedAt;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    @Column(nullable = false)
    private String createdBy;

    private String updatedBy;
    private String assignedTo;
    private String resolvedBy;

    @Column(columnDefinition = "TEXT")
    private String notes;

    private Boolean isActive;
    private Boolean isEscalated;
    private Boolean isAcknowledged;
    private Boolean isResolved;
    private Boolean isFalsePositive;

    // Enums
    public enum AnomalyType {
        NETWORK_TRAFFIC("Network Traffic"),
        PROTOCOL_VIOLATION("Protocol Violation"),
        BEHAVIORAL_CHANGE("Behavioral Change"),
        ACCESS_PATTERN("Access Pattern"),
        COMMUNICATION_PATTERN("Communication Pattern"),
        TIMING_ANOMALY("Timing Anomaly"),
        VOLUME_ANOMALY("Volume Anomaly"),
        GEOGRAPHICAL_ANOMALY("Geographical Anomaly"),
        PROTOCOL_ANOMALY("Protocol Anomaly"),
        PAYLOAD_ANOMALY("Payload Anomaly"),
        FREQUENCY_ANOMALY("Frequency Anomaly"),
        SEQUENCE_ANOMALY("Sequence Anomaly"),
        THRESHOLD_VIOLATION("Threshold Violation"),
        PATTERN_DEVIATION("Pattern Deviation"),
        STATISTICAL_ANOMALY("Statistical Anomaly"),
        MACHINE_LEARNING_ANOMALY("Machine Learning Anomaly"),
        RULE_BASED_ANOMALY("Rule Based Anomaly"),
        SIGNATURE_BASED_ANOMALY("Signature Based Anomaly"),
        HEURISTIC_ANOMALY("Heuristic Anomaly"),
        OTHER("Other");

        private final String displayName;

        AnomalyType(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    public enum AnomalySeverity {
        CRITICAL("Critical"),
        HIGH("High"),
        MEDIUM("Medium"),
        LOW("Low"),
        INFO("Info");

        private final String displayName;

        AnomalySeverity(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    public enum AnomalyStatus {
        DETECTED("Detected"),
        ACKNOWLEDGED("Acknowledged"),
        INVESTIGATING("Investigating"),
        ESCALATED("Escalated"),
        RESOLVED("Resolved"),
        FALSE_POSITIVE("False Positive"),
        IGNORED("Ignored"),
        CLOSED("Closed");

        private final String displayName;

        AnomalyStatus(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    // Helper methods
    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        detectedAt = LocalDateTime.now();
        isActive = true;
        if (status == null) {
            status = AnomalyStatus.DETECTED;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }
} 