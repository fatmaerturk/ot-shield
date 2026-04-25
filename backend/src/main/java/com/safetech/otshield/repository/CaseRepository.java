package com.safetech.otshield.repository;

import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.Case;
import com.safetech.otshield.model.CasePriority;
import com.safetech.otshield.model.CaseStatus;
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
public interface CaseRepository extends JpaRepository<Case, String> {

    Optional<Case> findByCaseNumber(String caseNumber);

    List<Case> findByStatus(CaseStatus status);
    Page<Case> findByStatus(CaseStatus status, Pageable pageable);
    List<Case> findByStatusIn(List<CaseStatus> statuses);

    List<Case> findByPriority(CasePriority priority);
    List<Case> findByAssigneeId(String assigneeId);

    long countByStatus(CaseStatus status);
    long countByPriority(CasePriority priority);
    long countBySeverity(AlertSeverity severity);

    @Query("SELECT COUNT(c) FROM Case c WHERE c.status IN :statuses")
    long countByStatusIn(@Param("statuses") List<CaseStatus> statuses);

    @Query("SELECT COUNT(c) FROM Case c WHERE c.resolvedAt >= :start")
    long countResolvedSince(@Param("start") LocalDateTime start);

    @Query("SELECT AVG(c.mttResolveSeconds) FROM Case c WHERE c.mttResolveSeconds IS NOT NULL AND c.resolvedAt >= :start")
    Double avgMttResolveSince(@Param("start") LocalDateTime start);

    @Query("SELECT AVG(c.mttAcknowledgeSeconds) FROM Case c WHERE c.mttAcknowledgeSeconds IS NOT NULL AND c.acknowledgedAt >= :start")
    Double avgMttAcknowledgeSince(@Param("start") LocalDateTime start);

    @Query("""
            SELECT c FROM Case c
            WHERE (:status IS NULL OR c.status = :status)
              AND (:priority IS NULL OR c.priority = :priority)
              AND (:assigneeId IS NULL OR c.assigneeId = :assigneeId)
              AND (:search IS NULL OR :search = '' OR
                   LOWER(c.title) LIKE LOWER(CONCAT('%', :search, '%')) OR
                   LOWER(c.description) LIKE LOWER(CONCAT('%', :search, '%')) OR
                   LOWER(c.caseNumber) LIKE LOWER(CONCAT('%', :search, '%')))
            """)
    Page<Case> findWithFilters(
            @Param("status") CaseStatus status,
            @Param("priority") CasePriority priority,
            @Param("assigneeId") String assigneeId,
            @Param("search") String search,
            Pageable pageable
    );

    @Query("SELECT MAX(c.caseNumber) FROM Case c WHERE c.caseNumber LIKE CONCAT(:prefix, '%')")
    Optional<String> findMaxCaseNumberForPrefix(@Param("prefix") String prefix);
}
