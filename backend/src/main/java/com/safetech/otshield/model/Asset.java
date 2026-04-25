package com.safetech.otshield.model;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Asset entity representing network devices and systems in the OT environment
 * Maps to the assets table in the database
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "assets")
public class Asset {
    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    @Column(nullable = false)
    private String name;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(nullable = false)
    private String ipAddress;

    @Column(name = "mac_address")
    private String macAddress;

    @Column(name = "asset_type", nullable = false)
    @Enumerated(EnumType.STRING)
    private AssetType assetType;

    @Column(name = "asset_category")
    @Enumerated(EnumType.STRING)
    private AssetCategory assetCategory;

    @Column(name = "purdue_level")
    @Enumerated(EnumType.STRING)
    private PurdueLevel purdueLevel;

    @Column(name = "manufacturer")
    private String manufacturer;

    @Column(name = "model")
    private String model;

    @Column(name = "serial_number")
    private String serialNumber;

    @Column(name = "firmware_version")
    private String firmwareVersion;

    @Column(name = "operating_system")
    private String operatingSystem;

    @Column(name = "os_version")
    private String osVersion;

    @Column(name = "hostname")
    private String hostname;

    @Column(name = "domain")
    private String domain;

    @Column(name = "location")
    private String location;

    @Column(name = "department")
    private String department;

    @Column(name = "owner")
    private String owner;

    @Column(name = "responsible_person")
    private String responsiblePerson;

    @Column(name = "contact_email")
    private String contactEmail;

    @Column(name = "contact_phone")
    private String contactPhone;

    @Column(name = "purchase_date")
    private LocalDateTime purchaseDate;

    @Column(name = "warranty_expiry")
    private LocalDateTime warrantyExpiry;

    @Column(name = "last_maintenance")
    private LocalDateTime lastMaintenance;

    @Column(name = "next_maintenance")
    private LocalDateTime nextMaintenance;

    @Column(name = "criticality_level")
    @Enumerated(EnumType.STRING)
    private CriticalityLevel criticalityLevel;

    @Column(name = "risk_score")
    private Integer riskScore;

    @Column(name = "vulnerability_count")
    private Integer vulnerabilityCount;

    @Column(name = "patch_level")
    private String patchLevel;

    @Column(name = "backup_status")
    @Enumerated(EnumType.STRING)
    private BackupStatus backupStatus;

    @Column(name = "monitoring_status")
    @Enumerated(EnumType.STRING)
    private MonitoringStatus monitoringStatus;

    @Column(name = "is_active")
    private Boolean isActive = true;

    @Column(name = "is_online")
    private Boolean isOnline = true;

    @Column(name = "last_seen")
    private LocalDateTime lastSeen;

    @Column(name = "first_seen")
    private LocalDateTime firstSeen;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "created_by")
    private String createdBy;

    @Column(name = "updated_by")
    private String updatedBy;

    @ElementCollection
    @CollectionTable(name = "asset_tags", joinColumns = @JoinColumn(name = "asset_id"))
    @Column(name = "tag")
    private List<String> tags;

    @Column(name = "notes", columnDefinition = "TEXT")
    private String notes;

    @Column(name = "custom_fields", columnDefinition = "TEXT")
    private String customFields; // JSON string for custom attributes

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
        if (firstSeen == null) {
            firstSeen = LocalDateTime.now();
        }
        if (lastSeen == null) {
            lastSeen = LocalDateTime.now();
        }
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    /**
     * Asset types based on OT environment
     */
    public enum AssetType {
        PLC("Programmable Logic Controller"),
        HMI("Human Machine Interface"),
        SCADA("Supervisory Control and Data Acquisition"),
        RTU("Remote Terminal Unit"),
        DCS("Distributed Control System"),
        WORKSTATION("Workstation"),
        SERVER("Server"),
        ROUTER("Router"),
        SWITCH("Switch"),
        FIREWALL("Firewall"),
        IDS_IPS("IDS/IPS"),
        HISTORIAN("Historian"),
        DATABASE("Database"),
        APPLICATION("Application"),
        SENSOR("Sensor"),
        ACTUATOR("Actuator"),
        CAMERA("Camera"),
        PRINTER("Printer"),
        OTHER("Other");

        private final String displayName;

        AssetType(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    /**
     * Asset categories for classification
     */
    public enum AssetCategory {
        CONTROL_SYSTEM("Control System"),
        NETWORK_INFRASTRUCTURE("Network Infrastructure"),
        SECURITY_DEVICE("Security Device"),
        DATA_STORAGE("Data Storage"),
        ENDPOINT("Endpoint"),
        FIELD_DEVICE("Field Device"),
        MONITORING("Monitoring"),
        BACKUP("Backup"),
        DEVELOPMENT("Development"),
        TESTING("Testing"),
        OTHER("Other");

        private final String displayName;

        AssetCategory(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    /**
     * Purdue model levels
     */
    public enum PurdueLevel {
        LEVEL_0("Level 0 - Process"),
        LEVEL_1("Level 1 - Basic Control"),
        LEVEL_2("Level 2 - Area Supervisory"),
        LEVEL_3("Level 3 - Site Business"),
        LEVEL_4("Level 4 - DMZ"),
        LEVEL_5("Level 5 - Enterprise");

        private final String displayName;

        PurdueLevel(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    /**
     * Criticality levels for assets
     */
    public enum CriticalityLevel {
        CRITICAL("Critical"),
        HIGH("High"),
        MEDIUM("Medium"),
        LOW("Low"),
        MINIMAL("Minimal");

        private final String displayName;

        CriticalityLevel(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    /**
     * Backup status
     */
    public enum BackupStatus {
        UP_TO_DATE("Up to Date"),
        OUTDATED("Outdated"),
        NOT_CONFIGURED("Not Configured"),
        FAILED("Failed"),
        IN_PROGRESS("In Progress");

        private final String displayName;

        BackupStatus(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }

    /**
     * Monitoring status
     */
    public enum MonitoringStatus {
        MONITORED("Monitored"),
        PARTIALLY_MONITORED("Partially Monitored"),
        NOT_MONITORED("Not Monitored"),
        DISABLED("Disabled");

        private final String displayName;

        MonitoringStatus(String displayName) {
            this.displayName = displayName;
        }

        public String getDisplayName() {
            return displayName;
        }
    }
} 