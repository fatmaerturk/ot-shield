package com.safetech.otshield.repository;

import com.safetech.otshield.model.NIS2Requirement;
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
 * Repository interface for NIS2Requirement entity
 * Provides database operations and custom queries
 */
@Repository
public interface NIS2RequirementRepository extends JpaRepository<NIS2Requirement, String> {

    // Basic CRUD operations
    Optional<NIS2Requirement> findByCode(String code);
    List<NIS2Requirement> findByTitleContainingIgnoreCase(String title);
    List<NIS2Requirement> findByDescriptionContainingIgnoreCase(String description);

    // Category-based queries
    List<NIS2Requirement> findByCategory(NIS2Requirement.RequirementCategory category);
    Page<NIS2Requirement> findByCategory(Pageable pageable, NIS2Requirement.RequirementCategory category);

    // Criticality-based queries
    List<NIS2Requirement> findByCriticality(NIS2Requirement.RequirementCriticality criticality);
    Page<NIS2Requirement> findByCriticality(Pageable pageable, NIS2Requirement.RequirementCriticality criticality);

    // Status-based queries
    List<NIS2Requirement> findByStatus(NIS2Requirement.ComplianceStatus status);
    Page<NIS2Requirement> findByStatus(Pageable pageable, NIS2Requirement.ComplianceStatus status);

    // Assignment-based queries
    List<NIS2Requirement> findByAssignedTo(String assignedTo);
    List<NIS2Requirement> findByAssignedToIsNull();

    // Due date queries
    List<NIS2Requirement> findByDueDateBefore(LocalDateTime date);
    List<NIS2Requirement> findByDueDateBetween(LocalDateTime startDate, LocalDateTime endDate);
    List<NIS2Requirement> findByDueDateBeforeAndStatusNot(LocalDateTime date, NIS2Requirement.ComplianceStatus status);

    // Assessment date queries
    List<NIS2Requirement> findByLastAssessmentDateBefore(LocalDateTime date);
    List<NIS2Requirement> findByNextAssessmentDateBefore(LocalDateTime date);

    // Score-based queries
    List<NIS2Requirement> findByComplianceScoreLessThan(Integer score);
    List<NIS2Requirement> findByRiskScoreGreaterThan(Integer score);

    // Tag-based queries
    List<NIS2Requirement> findByTagsContaining(String tag);

    // Complex queries
    @Query("SELECT r FROM NIS2Requirement r WHERE " +
           "(:category IS NULL OR r.category = :category) AND " +
           "(:criticality IS NULL OR r.criticality = :criticality) AND " +
           "(:status IS NULL OR r.status = :status) AND " +
           "(:assignedTo IS NULL OR r.assignedTo = :assignedTo)")
    Page<NIS2Requirement> findByFilters(
            @Param("category") NIS2Requirement.RequirementCategory category,
            @Param("criticality") NIS2Requirement.RequirementCriticality criticality,
            @Param("status") NIS2Requirement.ComplianceStatus status,
            @Param("assignedTo") String assignedTo,
            Pageable pageable);

    @Query("SELECT r FROM NIS2Requirement r WHERE " +
           "r.title LIKE %:searchTerm% OR " +
           "r.description LIKE %:searchTerm% OR " +
           "r.code LIKE %:searchTerm%")
    Page<NIS2Requirement> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    // Statistics queries
    @Query("SELECT COUNT(r) FROM NIS2Requirement r WHERE r.status = :status")
    Long countByStatus(@Param("status") NIS2Requirement.ComplianceStatus status);

    @Query("SELECT COUNT(r) FROM NIS2Requirement r WHERE r.category = :category")
    Long countByCategory(@Param("category") NIS2Requirement.RequirementCategory category);

    @Query("SELECT COUNT(r) FROM NIS2Requirement r WHERE r.criticality = :criticality")
    Long countByCriticality(@Param("criticality") NIS2Requirement.RequirementCriticality criticality);

    @Query("SELECT AVG(r.complianceScore) FROM NIS2Requirement r WHERE r.complianceScore IS NOT NULL")
    Double getAverageComplianceScore();

    @Query("SELECT AVG(r.riskScore) FROM NIS2Requirement r WHERE r.riskScore IS NOT NULL")
    Double getAverageRiskScore();

    // Overdue requirements
    @Query("SELECT r FROM NIS2Requirement r WHERE r.dueDate < :currentDate AND r.status != 'COMPLIANT'")
    List<NIS2Requirement> findOverdueRequirements(@Param("currentDate") LocalDateTime currentDate);

    // High-risk requirements
    @Query("SELECT r FROM NIS2Requirement r WHERE r.riskScore >= :minRiskScore ORDER BY r.riskScore DESC")
    List<NIS2Requirement> findHighRiskRequirements(@Param("minRiskScore") Integer minRiskScore);

    // Requirements due soon
    @Query("SELECT r FROM NIS2Requirement r WHERE r.dueDate BETWEEN :startDate AND :endDate")
    List<NIS2Requirement> findRequirementsDueBetween(
            @Param("startDate") LocalDateTime startDate,
            @Param("endDate") LocalDateTime endDate);
} 