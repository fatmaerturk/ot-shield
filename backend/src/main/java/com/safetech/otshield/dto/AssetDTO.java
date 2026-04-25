package com.safetech.otshield.dto;

import com.safetech.otshield.model.Asset;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Data Transfer Object for Asset entity
 * Used for API communication between frontend and backend
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AssetDTO {
    private String id;
    private String name;
    private String description;
    private String ipAddress;
    private String macAddress;
    private Asset.AssetType assetType;
    private Asset.AssetCategory assetCategory;
    private Asset.PurdueLevel purdueLevel;
    private String manufacturer;
    private String model;
    private String serialNumber;
    private String firmwareVersion;
    private String operatingSystem;
    private String osVersion;
    private String hostname;
    private String domain;
    private String location;
    private String department;
    private String owner;
    private String responsiblePerson;
    private String contactEmail;
    private String contactPhone;
    private LocalDateTime purchaseDate;
    private LocalDateTime warrantyExpiry;
    private LocalDateTime lastMaintenance;
    private LocalDateTime nextMaintenance;
    private Asset.CriticalityLevel criticalityLevel;
    private Integer riskScore;
    private Integer vulnerabilityCount;
    private String patchLevel;
    private Asset.BackupStatus backupStatus;
    private Asset.MonitoringStatus monitoringStatus;
    private Boolean isActive;
    private Boolean isOnline;
    private LocalDateTime lastSeen;
    private LocalDateTime firstSeen;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private String createdBy;
    private String updatedBy;
    private List<String> tags;
    private String notes;
    private String customFields;
} 