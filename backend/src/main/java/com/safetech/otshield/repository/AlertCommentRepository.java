package com.safetech.otshield.repository;

import com.safetech.otshield.model.Alert;
import com.safetech.otshield.mapper.AlertComment;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AlertCommentRepository extends JpaRepository<AlertComment, String> {
    
    // Basic finders
    List<AlertComment> findByAlert(Alert alert);
    List<AlertComment> findByAlertId(String alertId);
    Page<AlertComment> findByAlertId(String alertId, Pageable pageable);
    
    // Created by queries
    List<AlertComment> findByCreatedBy(String createdBy);
    List<AlertComment> findByCreatedByAndAlertId(String createdBy, String alertId);
    
    // Time-based queries
    List<AlertComment> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);
    List<AlertComment> findByCreatedAtAfter(LocalDateTime date);
    List<AlertComment> findByCreatedAtBefore(LocalDateTime date);
    
    // Internal/External comments
    List<AlertComment> findByIsInternal(Boolean isInternal);
    List<AlertComment> findByIsInternalTrue();
    List<AlertComment> findByIsInternalFalse();
    
    // Comment type queries
    List<AlertComment> findByCommentType(AlertComment.CommentType commentType);
    List<AlertComment> findByCommentTypeIn(List<AlertComment.CommentType> commentTypes);
    
    // Complex queries
    @Query("SELECT c FROM AlertComment c WHERE c.alert.id = :alertId AND c.isInternal = :isInternal")
    List<AlertComment> findByAlertIdAndIsInternal(@Param("alertId") String alertId, 
                                                 @Param("isInternal") Boolean isInternal);
    
    @Query("SELECT c FROM AlertComment c WHERE c.alert.id = :alertId AND c.commentType = :commentType")
    List<AlertComment> findByAlertIdAndCommentType(@Param("alertId") String alertId, 
                                                  @Param("commentType") AlertComment.CommentType commentType);
    
    @Query("SELECT c FROM AlertComment c WHERE c.createdBy = :createdBy AND c.createdAt >= :startDate")
    List<AlertComment> findByCreatedByAndCreatedAtAfter(@Param("createdBy") String createdBy, 
                                                       @Param("startDate") LocalDateTime startDate);
    
    // Search queries
    @Query("SELECT c FROM AlertComment c WHERE LOWER(c.commentText) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    Page<AlertComment> searchComments(@Param("searchTerm") String searchTerm, Pageable pageable);
    
    @Query("SELECT c FROM AlertComment c WHERE c.alert.id = :alertId AND LOWER(c.commentText) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    List<AlertComment> searchCommentsByAlertId(@Param("alertId") String alertId, 
                                              @Param("searchTerm") String searchTerm);
    
    // Count queries
    long countByAlert(Alert alert);
    long countByAlertId(String alertId);
    long countByCreatedBy(String createdBy);
    long countByCommentType(AlertComment.CommentType commentType);
    long countByIsInternal(Boolean isInternal);
    long countByAttachmentsIsNotNull();
    long countByAttachmentsIsNull();
    
    @Query("SELECT COUNT(c) FROM AlertComment c WHERE c.alert.id = :alertId AND c.createdAt >= :startDate")
    long countByAlertIdAndCreatedAtAfter(@Param("alertId") String alertId, 
                                        @Param("startDate") LocalDateTime startDate);
    
    // Latest comments
    @Query("SELECT c FROM AlertComment c WHERE c.alert.id = :alertId ORDER BY c.createdAt DESC")
    List<AlertComment> findLatestCommentsByAlertId(@Param("alertId") String alertId, Pageable pageable);
    
    // Comments by date range
    @Query("SELECT c FROM AlertComment c WHERE c.alert.id = :alertId AND c.createdAt BETWEEN :startDate AND :endDate ORDER BY c.createdAt DESC")
    List<AlertComment> findByAlertIdAndDateRange(@Param("alertId") String alertId, 
                                                @Param("startDate") LocalDateTime startDate, 
                                                @Param("endDate") LocalDateTime endDate);
    
    // Comments with attachments
    List<AlertComment> findByAttachmentsIsNotNull();
    List<AlertComment> findByAttachmentsIsNull();
    
    @Query("SELECT c FROM AlertComment c WHERE c.alert.id = :alertId AND c.attachments IS NOT NULL")
    List<AlertComment> findCommentsWithAttachmentsByAlertId(@Param("alertId") String alertId);
} 