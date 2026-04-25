package com.safetech.otshield.repository;

import com.safetech.otshield.model.Asset;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for Asset entity
 * Provides data access methods for asset management
 */
@Repository
public interface AssetRepository extends JpaRepository<Asset, String> {

    /**
     * Find asset by IP address
     */
    Optional<Asset> findByIpAddress(String ipAddress);

    /**
     * Find asset by MAC address
     */
    Optional<Asset> findByMacAddress(String macAddress);

    /**
     * Find asset by hostname
     */
    Optional<Asset> findByHostname(String hostname);

    /**
     * Find assets by asset type
     */
    List<Asset> findByAssetType(Asset.AssetType assetType);

    /**
     * Find assets by asset category
     */
    List<Asset> findByAssetCategory(Asset.AssetCategory assetCategory);

    /**
     * Find assets by Purdue level
     */
    List<Asset> findByPurdueLevel(Asset.PurdueLevel purdueLevel);

    /**
     * Find assets by manufacturer
     */
    List<Asset> findByManufacturer(String manufacturer);

    /**
     * Find assets by location
     */
    List<Asset> findByLocation(String location);

    /**
     * Find assets by department
     */
    List<Asset> findByDepartment(String department);

    /**
     * Find assets by criticality level
     */
    List<Asset> findByCriticalityLevel(Asset.CriticalityLevel criticalityLevel);

    /**
     * Find active assets
     */
    List<Asset> findByIsActiveTrue();

    /**
     * Find online assets
     */
    List<Asset> findByIsOnlineTrue();

    /**
     * Find assets by monitoring status
     */
    List<Asset> findByMonitoringStatus(Asset.MonitoringStatus monitoringStatus);

    /**
     * Find assets by backup status
     */
    List<Asset> findByBackupStatus(Asset.BackupStatus backupStatus);

    /**
     * Find assets that haven't been seen recently
     */
    @Query("SELECT a FROM Asset a WHERE a.lastSeen < :cutoffDate")
    List<Asset> findAssetsNotSeenSince(@Param("cutoffDate") LocalDateTime cutoffDate);

    /**
     * Find assets with high risk scores
     */
    @Query("SELECT a FROM Asset a WHERE a.riskScore >= :minRiskScore ORDER BY a.riskScore DESC")
    List<Asset> findAssetsWithHighRiskScore(@Param("minRiskScore") Integer minRiskScore);

    /**
     * Find assets with vulnerabilities
     */
    @Query("SELECT a FROM Asset a WHERE a.vulnerabilityCount > 0 ORDER BY a.vulnerabilityCount DESC")
    List<Asset> findAssetsWithVulnerabilities();

    /**
     * Find assets by name containing (case-insensitive)
     */
    @Query("SELECT a FROM Asset a WHERE LOWER(a.name) LIKE LOWER(CONCAT('%', :name, '%'))")
    List<Asset> findByNameContainingIgnoreCase(@Param("name") String name);

    /**
     * Find assets by IP address containing
     */
    @Query("SELECT a FROM Asset a WHERE a.ipAddress LIKE CONCAT('%', :ip, '%')")
    List<Asset> findByIpAddressContaining(@Param("ip") String ip);

    /**
     * Find assets by tag
     */
    @Query("SELECT a FROM Asset a WHERE :tag MEMBER OF a.tags")
    List<Asset> findByTag(@Param("tag") String tag);

    /**
     * Find assets by multiple tags
     */
    @Query("SELECT a FROM Asset a WHERE EXISTS (SELECT 1 FROM a.tags t WHERE t IN :tags)")
    List<Asset> findByTags(@Param("tags") List<String> tags);

    /**
     * Find assets by owner
     */
    List<Asset> findByOwner(String owner);

    /**
     * Find assets by responsible person
     */
    List<Asset> findByResponsiblePerson(String responsiblePerson);

    /**
     * Find assets that need maintenance soon
     */
    @Query("SELECT a FROM Asset a WHERE a.nextMaintenance <= :deadline AND a.isActive = true")
    List<Asset> findAssetsNeedingMaintenance(@Param("deadline") LocalDateTime deadline);

    /**
     * Find assets with expired warranty
     */
    @Query("SELECT a FROM Asset a WHERE a.warrantyExpiry <= :currentDate")
    List<Asset> findAssetsWithExpiredWarranty(@Param("currentDate") LocalDateTime currentDate);

    /**
     * Count assets by asset type
     */
    @Query("SELECT a.assetType, COUNT(a) FROM Asset a GROUP BY a.assetType")
    List<Object[]> countByAssetType();

    /**
     * Count assets by Purdue level
     */
    @Query("SELECT a.purdueLevel, COUNT(a) FROM Asset a GROUP BY a.purdueLevel")
    List<Object[]> countByPurdueLevel();

    /**
     * Count assets by criticality level
     */
    @Query("SELECT a.criticalityLevel, COUNT(a) FROM Asset a GROUP BY a.criticalityLevel")
    List<Object[]> countByCriticalityLevel();

    /**
     * Find assets with pagination and search
     */
    @Query("SELECT a FROM Asset a WHERE " +
           "(:name IS NULL OR LOWER(a.name) LIKE LOWER(CONCAT('%', :name, '%'))) AND " +
           "(:ipAddress IS NULL OR a.ipAddress LIKE CONCAT('%', :ipAddress, '%')) AND " +
           "(:assetType IS NULL OR a.assetType = :assetType) AND " +
           "(:purdueLevel IS NULL OR a.purdueLevel = :purdueLevel) AND " +
           "(:criticalityLevel IS NULL OR a.criticalityLevel = :criticalityLevel) AND " +
           "(:isActive IS NULL OR a.isActive = :isActive)")
    Page<Asset> findAssetsWithFilters(
            @Param("name") String name,
            @Param("ipAddress") String ipAddress,
            @Param("assetType") Asset.AssetType assetType,
            @Param("purdueLevel") Asset.PurdueLevel purdueLevel,
            @Param("criticalityLevel") Asset.CriticalityLevel criticalityLevel,
            @Param("isActive") Boolean isActive,
            Pageable pageable
    );

    /**
     * Find assets created by a specific user
     */
    List<Asset> findByCreatedBy(String createdBy);

    /**
     * Find assets updated by a specific user
     */
    List<Asset> findByUpdatedBy(String updatedBy);

    /**
     * Find assets created within a date range
     */
    @Query("SELECT a FROM Asset a WHERE a.createdAt BETWEEN :startDate AND :endDate")
    List<Asset> findByCreatedAtBetween(@Param("startDate") LocalDateTime startDate, 
                                      @Param("endDate") LocalDateTime endDate);

    /**
     * Find assets updated within a date range
     */
    @Query("SELECT a FROM Asset a WHERE a.updatedAt BETWEEN :startDate AND :endDate")
    List<Asset> findByUpdatedAtBetween(@Param("startDate") LocalDateTime startDate, 
                                      @Param("endDate") LocalDateTime endDate);

    /**
     * Find offline assets
     */
    List<Asset> findByIsOnlineFalse();

    /**
     * Find assets with risk score greater than specified value
     */
    List<Asset> findByRiskScoreGreaterThan(Integer minRiskScore);

    /**
     * Count active assets
     */
    Long countByIsActiveTrue();

    /**
     * Count online assets
     */
    Long countByIsOnlineTrue();

    /**
     * Count offline assets
     */
    Long countByIsOnlineFalse();

    /**
     * Count assets with vulnerabilities
     */
    Long countByVulnerabilityCountGreaterThan(Integer minVulnerabilityCount);

    /**
     * Count assets with risk score greater than specified value
     */
    Long countByRiskScoreGreaterThan(Integer minRiskScore);
} 