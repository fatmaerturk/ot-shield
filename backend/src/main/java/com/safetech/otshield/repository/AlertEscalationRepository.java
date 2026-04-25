package com.safetech.otshield.repository;

import com.safetech.otshield.model.Alert;
import com.safetech.otshield.mapper.AlertEscalation;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AlertEscalationRepository extends JpaRepository<AlertEscalation, String> {
    
    // Basic finders
    List<AlertEscalation> findByAlert(Alert alert);
    List<AlertEscalation> findByAlertId(String alertId);
    Page<AlertEscalation> findByAlertId(String alertId, Pageable pageable);
    
    // Status-based queries
    List<AlertEscalation> findByStatus(AlertEscalation.EscalationStatus status);
    List<AlertEscalation> findByStatusIn(List<AlertEscalation.EscalationStatus> statuses);
    
    // Level-based queries
    List<AlertEscalation> findByEscalationLevel(Integer escalationLevel);
    List<AlertEscalation> findByEscalationLevelGreaterThan(Integer escalationLevel);
    List<AlertEscalation> findByEscalationLevelLessThan(Integer escalationLevel);
    List<AlertEscalation> findByEscalationLevelBetween(Integer minLevel, Integer maxLevel);
    
    // Escalated to/from queries
    List<AlertEscalation> findByEscalatedTo(String escalatedTo);
    List<AlertEscalation> findByEscalatedFrom(String escalatedFrom);
    List<AlertEscalation> findByEscalatedToAndStatus(String escalatedTo, AlertEscalation.EscalationStatus status);
    
    // Time-based queries
    List<AlertEscalation> findByEscalationTimeBetween(LocalDateTime startDate, LocalDateTime endDate);
    List<AlertEscalation> findByEscalationTimeAfter(LocalDateTime date);
    List<AlertEscalation> findByEscalationTimeBefore(LocalDateTime date);
    List<AlertEscalation> findByResponseTimeBetween(LocalDateTime startDate, LocalDateTime endDate);
    List<AlertEscalation> findByResolutionTimeBetween(LocalDateTime startDate, LocalDateTime endDate);
    
    // Auto-escalation queries
    List<AlertEscalation> findByAutoEscalate(Boolean autoEscalate);
    List<AlertEscalation> findByAutoEscalateTrue();
    List<AlertEscalation> findByAutoEscalateFalse();
    
    // Policy-based queries
    List<AlertEscalation> findByEscalationPolicy(String escalationPolicy);
    List<AlertEscalation> findByEscalationPolicyIn(List<String> policies);
    
    // Complex queries
    @Query("SELECT e FROM AlertEscalation e WHERE e.alert.id = :alertId AND e.status = :status")
    List<AlertEscalation> findByAlertIdAndStatus(@Param("alertId") String alertId, 
                                                @Param("status") AlertEscalation.EscalationStatus status);
    
    @Query("SELECT e FROM AlertEscalation e WHERE e.alert.id = :alertId AND e.escalationLevel = :level")
    List<AlertEscalation> findByAlertIdAndLevel(@Param("alertId") String alertId, 
                                               @Param("level") Integer level);
    
    @Query("SELECT e FROM AlertEscalation e WHERE e.escalatedTo = :escalatedTo AND e.status = 'ACTIVE'")
    List<AlertEscalation> findActiveEscalationsForUser(@Param("escalatedTo") String escalatedTo);
    
    @Query("SELECT e FROM AlertEscalation e WHERE e.escalationTime >= :startDate AND e.status = :status")
    List<AlertEscalation> findByEscalationTimeAfterAndStatus(@Param("startDate") LocalDateTime startDate, 
                                                            @Param("status") AlertEscalation.EscalationStatus status);
    
    // Active escalations
    @Query("SELECT e FROM AlertEscalation e WHERE e.status = 'ACTIVE'")
    List<AlertEscalation> findActiveEscalations();
    
    @Query("SELECT e FROM AlertEscalation e WHERE e.status = 'ACTIVE' AND e.escalationTime <= :timeout")
    List<AlertEscalation> findTimedOutEscalations(@Param("timeout") LocalDateTime timeout);
    
    // Timeout queries - fixed version
    @Query("SELECT e FROM AlertEscalation e WHERE e.status = 'ACTIVE' AND e.escalationTime <= :currentTime")
    List<AlertEscalation> findEscalationsExceedingTimeout(@Param("currentTime") LocalDateTime currentTime);
    
    // Search queries
    @Query("SELECT e FROM AlertEscalation e WHERE LOWER(e.escalationReason) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
           "OR LOWER(e.notes) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
           "OR LOWER(e.escalatedTo) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    Page<AlertEscalation> searchEscalations(@Param("searchTerm") String searchTerm, Pageable pageable);
    
    // Count queries
    long countByAlert(Alert alert);
    long countByAlertId(String alertId);
    long countByStatus(AlertEscalation.EscalationStatus status);
    long countByEscalationLevel(Integer escalationLevel);
    long countByEscalatedTo(String escalatedTo);
    long countByEscalatedFrom(String escalatedFrom);
    long countByAutoEscalate(Boolean autoEscalate);
    
    @Query("SELECT COUNT(e) FROM AlertEscalation e WHERE e.alert.id = :alertId AND e.status = :status")
    long countByAlertIdAndStatus(@Param("alertId") String alertId, 
                                @Param("status") AlertEscalation.EscalationStatus status);
    
    @Query("SELECT COUNT(e) FROM AlertEscalation e WHERE e.escalationTime >= :startDate")
    long countByEscalationTimeAfter(@Param("startDate") LocalDateTime startDate);
    
    @Query("SELECT COUNT(e) FROM AlertEscalation e WHERE e.escalationTime BETWEEN :startDate AND :endDate")
    long countByEscalationTimeBetween(@Param("startDate") LocalDateTime startDate, 
                                     @Param("endDate") LocalDateTime endDate);
    
    // Response time statistics
    @Query("SELECT e FROM AlertEscalation e WHERE e.responseTime IS NOT NULL AND e.escalationTime >= :startDate")
    List<AlertEscalation> findEscalationsWithResponseTimeAfter(@Param("startDate") LocalDateTime startDate);
    
    // Resolution time statistics
    @Query("SELECT e FROM AlertEscalation e WHERE e.resolutionTime IS NOT NULL AND e.escalationTime >= :startDate")
    List<AlertEscalation> findEscalationsWithResolutionTimeAfter(@Param("startDate") LocalDateTime startDate);
    
    // Latest escalations
    @Query("SELECT e FROM AlertEscalation e WHERE e.alert.id = :alertId ORDER BY e.escalationTime DESC")
    List<AlertEscalation> findLatestEscalationsByAlertId(@Param("alertId") String alertId, Pageable pageable);
    
    // Escalations by date range
    @Query("SELECT e FROM AlertEscalation e WHERE e.alert.id = :alertId AND e.escalationTime BETWEEN :startDate AND :endDate ORDER BY e.escalationTime DESC")
    List<AlertEscalation> findByAlertIdAndDateRange(@Param("alertId") String alertId, 
                                                   @Param("startDate") LocalDateTime startDate, 
                                                   @Param("endDate") LocalDateTime endDate);
    
    // Escalations with notes
    List<AlertEscalation> findByNotesIsNotNull();
    List<AlertEscalation> findByNotesIsNull();
    
    @Query("SELECT e FROM AlertEscalation e WHERE e.alert.id = :alertId AND e.notes IS NOT NULL")
    List<AlertEscalation> findEscalationsWithNotesByAlertId(@Param("alertId") String alertId);
} 