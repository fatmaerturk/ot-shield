package com.safetech.otshield.repository;

import com.safetech.otshield.mapper.AlertRule;
import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.AlertType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface AlertRuleRepository extends JpaRepository<AlertRule, String> {
    
    // Basic finders
    Optional<AlertRule> findById(String id);
    Optional<AlertRule> findByName(String name);
    
    // Enabled/Disabled rules
    List<AlertRule> findByEnabled(Boolean enabled);
    List<AlertRule> findByEnabledTrue();
    List<AlertRule> findByEnabledFalse();
    
    // Severity-based queries
    List<AlertRule> findBySeverity(AlertSeverity severity);
    List<AlertRule> findBySeverityIn(List<AlertSeverity> severities);
    
    // Type-based queries
    List<AlertRule> findByType(AlertType type);
    List<AlertRule> findByTypeIn(List<AlertType> types);
    
    // Category-based queries
    List<AlertRule> findByCategory(String category);
    List<AlertRule> findByCategoryIn(List<String> categories);
    
    // Source system queries
    List<AlertRule> findBySourceSystemsContaining(String sourceSystem);
    
    // Priority-based queries
    List<AlertRule> findByPriority(Integer priority);
    List<AlertRule> findByPriorityGreaterThan(Integer priority);
    List<AlertRule> findByPriorityLessThan(Integer priority);
    List<AlertRule> findByPriorityBetween(Integer minPriority, Integer maxPriority);
    
    // Suppression queries
    List<AlertRule> findBySuppressionEnabled(Boolean suppressionEnabled);
    List<AlertRule> findBySuppressionEnabledTrue();
    
    // Created/Updated by queries
    List<AlertRule> findByCreatedBy(String createdBy);
    List<AlertRule> findByUpdatedBy(String updatedBy);
    
    // Complex queries
    @Query("SELECT r FROM AlertRule r WHERE r.enabled = true AND r.severity IN :severities")
    List<AlertRule> findActiveRulesBySeverity(@Param("severities") List<AlertSeverity> severities);
    
    @Query("SELECT r FROM AlertRule r WHERE r.enabled = true AND r.type IN :types")
    List<AlertRule> findActiveRulesByType(@Param("types") List<AlertType> types);
    
    @Query("SELECT r FROM AlertRule r WHERE r.enabled = true AND r.category = :category")
    List<AlertRule> findActiveRulesByCategory(@Param("category") String category);
    
    @Query("SELECT r FROM AlertRule r WHERE r.enabled = true AND r.sourceSystems LIKE %:sourceSystem%")
    List<AlertRule> findActiveRulesBySourceSystem(@Param("sourceSystem") String sourceSystem);
    
    // Search queries
    @Query("SELECT r FROM AlertRule r WHERE LOWER(r.name) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
           "OR LOWER(r.description) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
           "OR LOWER(r.category) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    Page<AlertRule> searchRules(@Param("searchTerm") String searchTerm, Pageable pageable);
    
    // Tag-based queries
    @Query("SELECT r FROM AlertRule r JOIN r.tags t WHERE t = :tag")
    List<AlertRule> findByTag(@Param("tag") String tag);
    
    // Notification channel queries
    @Query("SELECT r FROM AlertRule r WHERE r.notificationChannels LIKE %:channel%")
    List<AlertRule> findByNotificationChannel(@Param("channel") String channel);
    
    // Count queries
    long countByEnabled(Boolean enabled);
    long countBySeverity(AlertSeverity severity);
    long countByType(AlertType type);
    long countByCategory(String category);
    long countByCreatedBy(String createdBy);
    
    // Find rules by multiple criteria
    @Query("SELECT r FROM AlertRule r WHERE r.enabled = true AND r.severity IN :severities AND r.type IN :types")
    List<AlertRule> findActiveRulesBySeverityAndType(@Param("severities") List<AlertSeverity> severities, 
                                                    @Param("types") List<AlertType> types);
    
    // Find rules with high priority
    @Query("SELECT r FROM AlertRule r WHERE r.enabled = true AND r.priority <= :maxPriority ORDER BY r.priority ASC")
    List<AlertRule> findHighPriorityActiveRules(@Param("maxPriority") Integer maxPriority);
    
    // Find rules by suppression duration
    List<AlertRule> findBySuppressionDurationMinutes(Integer duration);
    List<AlertRule> findBySuppressionDurationMinutesGreaterThan(Integer duration);
    List<AlertRule> findBySuppressionDurationMinutesLessThan(Integer duration);
} 