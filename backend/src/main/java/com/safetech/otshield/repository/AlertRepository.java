package com.safetech.otshield.repository;

import com.safetech.otshield.model.Alert;
import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.AlertStatus;
import com.safetech.otshield.model.AlertType;
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
public interface AlertRepository extends JpaRepository<Alert, String> {
    
    // Basic finders
    Optional<Alert> findById(String id);
    
    // Status-based queries
    List<Alert> findByStatus(AlertStatus status);
    Page<Alert> findByStatus(AlertStatus status, Pageable pageable);
    List<Alert> findByStatusIn(List<AlertStatus> statuses);
    
    // Severity-based queries
    List<Alert> findBySeverity(AlertSeverity severity);
    Page<Alert> findBySeverity(AlertSeverity severity, Pageable pageable);
    List<Alert> findBySeverityIn(List<AlertSeverity> severities);
    
    // Type-based queries
    List<Alert> findByType(AlertType type);
    Page<Alert> findByType(AlertType type, Pageable pageable);
    List<Alert> findByTypeIn(List<AlertType> types);
    
    // Source-based queries
    List<Alert> findBySource(String source);
    List<Alert> findBySourceIn(List<String> sources);
    
    // IP-based queries
    List<Alert> findBySourceIp(String sourceIp);
    List<Alert> findByDestinationIp(String destinationIp);
    List<Alert> findBySourceIpOrDestinationIp(String sourceIp, String destinationIp);
    
    // Time-based queries
    List<Alert> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);
    List<Alert> findByCreatedAtAfter(LocalDateTime date);
    List<Alert> findByCreatedAtBefore(LocalDateTime date);
    
    // Assignment queries
    List<Alert> findByAssignedTo(String assignedTo);
    List<Alert> findByAssignedToIsNull();
    List<Alert> findByAssignedToIsNotNull();
    
    // Acknowledgment queries
    List<Alert> findByAcknowledged(Boolean acknowledged);
    List<Alert> findByAcknowledgedBy(String acknowledgedBy);
    
    // Escalation queries
    List<Alert> findByEscalated(Boolean escalated);
    List<Alert> findByEscalatedTo(String escalatedTo);
    
    // False positive queries
    List<Alert> findByFalsePositive(Boolean falsePositive);
    
    // Complex queries
    @Query("SELECT a FROM Alert a WHERE a.severity IN :severities AND a.status IN :statuses")
    List<Alert> findBySeverityInAndStatusIn(@Param("severities") List<AlertSeverity> severities, 
                                           @Param("statuses") List<AlertStatus> statuses);
    
    @Query("SELECT a FROM Alert a WHERE a.createdAt >= :startDate AND a.severity = :severity")
    List<Alert> findByCreatedAtAfterAndSeverity(@Param("startDate") LocalDateTime startDate, 
                                               @Param("severity") AlertSeverity severity);
    
    @Query("SELECT a FROM Alert a WHERE a.sourceIp = :ip OR a.destinationIp = :ip")
    List<Alert> findByIpAddress(@Param("ip") String ip);
    
    // Count queries
    long countByStatus(AlertStatus status);
    long countBySeverity(AlertSeverity severity);
    long countByType(AlertType type);
    long countBySource(String source);
    long countByAssignedTo(String assignedTo);
    long countByAcknowledged(Boolean acknowledged);
    long countByEscalated(Boolean escalated);
    long countByFalsePositive(Boolean falsePositive);
    
    @Query("SELECT COUNT(a) FROM Alert a WHERE a.createdAt >= :startDate")
    long countByCreatedAtAfter(@Param("startDate") LocalDateTime startDate);
    
    @Query("SELECT COUNT(a) FROM Alert a WHERE a.createdAt BETWEEN :startDate AND :endDate")
    long countByCreatedAtBetween(@Param("startDate") LocalDateTime startDate, 
                                @Param("endDate") LocalDateTime endDate);
    
    // Search queries
    @Query("SELECT a FROM Alert a WHERE LOWER(a.title) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
           "OR LOWER(a.description) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
           "OR LOWER(a.source) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    Page<Alert> searchAlerts(@Param("searchTerm") String searchTerm, Pageable pageable);
    
    // Tag-based queries
    @Query("SELECT a FROM Alert a JOIN a.tags t WHERE t = :tag")
    List<Alert> findByTag(@Param("tag") String tag);
    
    // Risk score queries
    List<Alert> findByRiskScoreGreaterThan(Integer riskScore);
    List<Alert> findByRiskScoreLessThan(Integer riskScore);
    List<Alert> findByRiskScoreBetween(Integer minScore, Integer maxScore);
    
    // Confidence score queries
    List<Alert> findByConfidenceScoreGreaterThan(Integer confidenceScore);
    List<Alert> findByConfidenceScoreLessThan(Integer confidenceScore);
    List<Alert> findByConfidenceScoreBetween(Integer minScore, Integer maxScore);
} 