package com.safetech.otshield.repository;

import com.safetech.otshield.model.Anomaly;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface AnomalyRepository extends JpaRepository<Anomaly, String> {

    // Basic find methods
    Optional<Anomaly> findByTitle(String title);
    List<Anomaly> findBySourceIp(String sourceIp);
    List<Anomaly> findByDestinationIp(String destinationIp);
    List<Anomaly> findByProtocol(String protocol);
    List<Anomaly> findByAssetType(String assetType);
    List<Anomaly> findByPurdueLevel(String purdueLevel);
    List<Anomaly> findByManufacturer(String manufacturer);
    List<Anomaly> findByLocation(String location);
    List<Anomaly> findByDepartment(String department);
    List<Anomaly> findByAssignedTo(String assignedTo);
    List<Anomaly> findByResolvedBy(String resolvedBy);

    // Status and severity based queries
    List<Anomaly> findByStatus(Anomaly.AnomalyStatus status);
    List<Anomaly> findBySeverity(Anomaly.AnomalySeverity severity);
    List<Anomaly> findByStatusAndSeverity(Anomaly.AnomalyStatus status, Anomaly.AnomalySeverity severity);
    List<Anomaly> findByIsActive(Boolean isActive);
    List<Anomaly> findByIsEscalated(Boolean isEscalated);
    List<Anomaly> findByIsAcknowledged(Boolean isAcknowledged);
    List<Anomaly> findByIsResolved(Boolean isResolved);
    List<Anomaly> findByIsFalsePositive(Boolean isFalsePositive);

    // Type based queries
    List<Anomaly> findByAnomalyType(Anomaly.AnomalyType anomalyType);
    List<Anomaly> findByAnomalyTypeAndSeverity(Anomaly.AnomalyType anomalyType, Anomaly.AnomalySeverity severity);

    // Date range queries
    List<Anomaly> findByDetectedAtBetween(LocalDateTime startDate, LocalDateTime endDate);
    List<Anomaly> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);
    List<Anomaly> findByResolvedAtBetween(LocalDateTime startDate, LocalDateTime endDate);
    List<Anomaly> findByDetectedAtAfter(LocalDateTime date);
    List<Anomaly> findByDetectedAtBefore(LocalDateTime date);

    // Score based queries
    List<Anomaly> findByConfidenceScoreGreaterThan(Double score);
    List<Anomaly> findByRiskScoreGreaterThan(Double score);
    List<Anomaly> findByConfidenceScoreBetween(Double minScore, Double maxScore);
    List<Anomaly> findByRiskScoreBetween(Double minScore, Double maxScore);

    // MITRE based queries
    List<Anomaly> findByMitreTactic(String mitreTactic);
    List<Anomaly> findByMitreTechnique(String mitreTechnique);
    List<Anomaly> findByMitreId(String mitreId);

    // Tag based queries
    @Query("SELECT a FROM Anomaly a JOIN a.tags t WHERE t = :tag")
    List<Anomaly> findByTag(@Param("tag") String tag);

    @Query("SELECT a FROM Anomaly a JOIN a.tags t WHERE t IN :tags")
    List<Anomaly> findByTagsIn(@Param("tags") List<String> tags);

    // Indicator based queries
    @Query("SELECT a FROM Anomaly a JOIN a.indicators i WHERE i = :indicator")
    List<Anomaly> findByIndicator(@Param("indicator") String indicator);

    @Query("SELECT a FROM Anomaly a JOIN a.indicators i WHERE i IN :indicators")
    List<Anomaly> findByIndicatorsIn(@Param("indicators") List<String> indicators);

    // Complex queries with pagination
    Page<Anomaly> findByStatus(Anomaly.AnomalyStatus status, Pageable pageable);
    Page<Anomaly> findBySeverity(Anomaly.AnomalySeverity severity, Pageable pageable);
    Page<Anomaly> findByAnomalyType(Anomaly.AnomalyType anomalyType, Pageable pageable);
    Page<Anomaly> findByIsActive(Boolean isActive, Pageable pageable);

    // Advanced search with multiple criteria
    @Query("SELECT a FROM Anomaly a WHERE " +
           "(:title IS NULL OR LOWER(a.title) LIKE LOWER(CONCAT('%', :title, '%'))) AND " +
           "(:sourceIp IS NULL OR a.sourceIp = :sourceIp) AND " +
           "(:destinationIp IS NULL OR a.destinationIp = :destinationIp) AND " +
           "(:protocol IS NULL OR a.protocol = :protocol) AND " +
           "(:assetType IS NULL OR a.assetType = :assetType) AND " +
           "(:purdueLevel IS NULL OR a.purdueLevel = :purdueLevel) AND " +
           "(:severity IS NULL OR a.severity = :severity) AND " +
           "(:status IS NULL OR a.status = :status) AND " +
           "(:anomalyType IS NULL OR a.anomalyType = :anomalyType) AND " +
           "(:isActive IS NULL OR a.isActive = :isActive)")
    Page<Anomaly> findAnomaliesWithFilters(
            @Param("title") String title,
            @Param("sourceIp") String sourceIp,
            @Param("destinationIp") String destinationIp,
            @Param("protocol") String protocol,
            @Param("assetType") String assetType,
            @Param("purdueLevel") String purdueLevel,
            @Param("severity") Anomaly.AnomalySeverity severity,
            @Param("status") Anomaly.AnomalyStatus status,
            @Param("anomalyType") Anomaly.AnomalyType anomalyType,
            @Param("isActive") Boolean isActive,
            Pageable pageable
    );

    // Statistics queries
    @Query("SELECT COUNT(a) FROM Anomaly a WHERE a.status = :status")
    Long countByStatus(@Param("status") Anomaly.AnomalyStatus status);

    @Query("SELECT COUNT(a) FROM Anomaly a WHERE a.severity = :severity")
    Long countBySeverity(@Param("severity") Anomaly.AnomalySeverity severity);

    @Query("SELECT COUNT(a) FROM Anomaly a WHERE a.anomalyType = :anomalyType")
    Long countByAnomalyType(@Param("anomalyType") Anomaly.AnomalyType anomalyType);

    @Query("SELECT COUNT(a) FROM Anomaly a WHERE a.isActive = :isActive")
    Long countByIsActive(@Param("isActive") Boolean isActive);

    @Query("SELECT COUNT(a) FROM Anomaly a WHERE a.detectedAt BETWEEN :startDate AND :endDate")
    Long countByDetectedAtBetween(@Param("startDate") LocalDateTime startDate, @Param("endDate") LocalDateTime endDate);

    // Top anomalies by various criteria
    @Query("SELECT a FROM Anomaly a WHERE a.detectedAt >= :since ORDER BY a.riskScore DESC")
    List<Anomaly> findTopAnomaliesByRiskScore(@Param("since") LocalDateTime since, Pageable pageable);

    @Query("SELECT a FROM Anomaly a WHERE a.detectedAt >= :since ORDER BY a.confidenceScore DESC")
    List<Anomaly> findTopAnomaliesByConfidenceScore(@Param("since") LocalDateTime since, Pageable pageable);

    // Recent anomalies
    @Query("SELECT a FROM Anomaly a ORDER BY a.detectedAt DESC")
    List<Anomaly> findRecentAnomalies(Pageable pageable);

    // Unresolved anomalies
    @Query("SELECT a FROM Anomaly a WHERE a.isResolved = false ORDER BY a.detectedAt DESC")
    List<Anomaly> findUnresolvedAnomalies(Pageable pageable);

    // Escalated anomalies
    @Query("SELECT a FROM Anomaly a WHERE a.isEscalated = true ORDER BY a.escalatedAt DESC")
    List<Anomaly> findEscalatedAnomalies(Pageable pageable);

    // Anomalies by asset
    @Query("SELECT a FROM Anomaly a WHERE a.hostname = :hostname OR a.sourceIp = :ip OR a.destinationIp = :ip")
    List<Anomaly> findByAsset(@Param("hostname") String hostname, @Param("ip") String ip);

    // Anomalies by location/department
    @Query("SELECT a FROM Anomaly a WHERE a.location = :location OR a.department = :department")
    List<Anomaly> findByLocationOrDepartment(@Param("location") String location, @Param("department") String department);
} 