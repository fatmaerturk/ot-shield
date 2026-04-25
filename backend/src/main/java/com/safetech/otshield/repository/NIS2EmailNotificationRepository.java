package com.safetech.otshield.repository;

import com.safetech.otshield.model.NIS2EmailNotification;
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
 * Repository interface for NIS2EmailNotification entity
 * Provides database operations and custom queries
 */
@Repository
public interface NIS2EmailNotificationRepository extends JpaRepository<NIS2EmailNotification, String> {

    // Basic CRUD operations
    Optional<NIS2EmailNotification> findByName(String name);
    List<NIS2EmailNotification> findByNameContainingIgnoreCase(String name);
    List<NIS2EmailNotification> findBySubjectContainingIgnoreCase(String subject);

    // Type-based queries
    List<NIS2EmailNotification> findByNotificationType(NIS2EmailNotification.NotificationType notificationType);
    Page<NIS2EmailNotification> findByNotificationType(Pageable pageable, NIS2EmailNotification.NotificationType notificationType);

    // Status-based queries
    List<NIS2EmailNotification> findByStatus(NIS2EmailNotification.NotificationStatus status);
    Page<NIS2EmailNotification> findByStatus(Pageable pageable, NIS2EmailNotification.NotificationStatus status);

    // Template-based queries
    List<NIS2EmailNotification> findByIsTemplate(Boolean isTemplate);
    List<NIS2EmailNotification> findByTemplateId(String templateId);

    // Recipient-based queries
    List<NIS2EmailNotification> findByRecipientsContaining(String recipient);
    List<NIS2EmailNotification> findByCcRecipientsContaining(String ccRecipient);
    List<NIS2EmailNotification> findByBccRecipientsContaining(String bccRecipient);

    // Date-based queries
    List<NIS2EmailNotification> findByLastSentAtBetween(LocalDateTime startDate, LocalDateTime endDate);
    List<NIS2EmailNotification> findByNextSendAtBefore(LocalDateTime date);
    List<NIS2EmailNotification> findByNextSendAtBetween(LocalDateTime startDate, LocalDateTime endDate);

    // Created by queries
    List<NIS2EmailNotification> findByCreatedBy(String createdBy);
    List<NIS2EmailNotification> findByUpdatedBy(String updatedBy);

    // Tag-based queries
    List<NIS2EmailNotification> findByTagsContaining(String tag);

    // Complex queries
    @Query("SELECT n FROM NIS2EmailNotification n WHERE " +
           "(:notificationType IS NULL OR n.notificationType = :notificationType) AND " +
           "(:status IS NULL OR n.status = :status) AND " +
           "(:isTemplate IS NULL OR n.isTemplate = :isTemplate)")
    Page<NIS2EmailNotification> findByFilters(
            @Param("notificationType") NIS2EmailNotification.NotificationType notificationType,
            @Param("status") NIS2EmailNotification.NotificationStatus status,
            @Param("isTemplate") Boolean isTemplate,
            Pageable pageable);

    @Query("SELECT n FROM NIS2EmailNotification n WHERE " +
           "n.name LIKE %:searchTerm% OR " +
           "n.subject LIKE %:searchTerm% OR " +
           "n.body LIKE %:searchTerm%")
    Page<NIS2EmailNotification> searchByTerm(@Param("searchTerm") String searchTerm, Pageable pageable);

    // Statistics queries
    @Query("SELECT COUNT(n) FROM NIS2EmailNotification n WHERE n.status = :status")
    Long countByStatus(@Param("status") NIS2EmailNotification.NotificationStatus status);

    @Query("SELECT COUNT(n) FROM NIS2EmailNotification n WHERE n.notificationType = :notificationType")
    Long countByNotificationType(@Param("notificationType") NIS2EmailNotification.NotificationType notificationType);

    @Query("SELECT COUNT(n) FROM NIS2EmailNotification n WHERE n.isTemplate = true")
    Long countTemplates();

    @Query("SELECT SUM(n.sentCount) FROM NIS2EmailNotification n WHERE n.sentCount IS NOT NULL")
    Long getTotalSentCount();

    @Query("SELECT SUM(n.failureCount) FROM NIS2EmailNotification n WHERE n.failureCount IS NOT NULL")
    Long getTotalFailureCount();

    // Active notifications
    @Query("SELECT n FROM NIS2EmailNotification n WHERE n.status = 'ACTIVE'")
    List<NIS2EmailNotification> findActiveNotifications();

    // Scheduled notifications
    @Query("SELECT n FROM NIS2EmailNotification n WHERE n.nextSendAt IS NOT NULL AND n.nextSendAt <= :date")
    List<NIS2EmailNotification> findScheduledNotifications(@Param("date") LocalDateTime date);

    // Notifications with failures
    @Query("SELECT n FROM NIS2EmailNotification n WHERE n.failureCount > 0 ORDER BY n.failureCount DESC")
    List<NIS2EmailNotification> findNotificationsWithFailures();

    // Recently sent notifications
    @Query("SELECT n FROM NIS2EmailNotification n WHERE n.lastSentAt >= :since ORDER BY n.lastSentAt DESC")
    List<NIS2EmailNotification> findRecentlySentNotifications(@Param("since") LocalDateTime since);

    // Notifications by recipient
    @Query("SELECT n FROM NIS2EmailNotification n WHERE " +
           ":recipient MEMBER OF n.recipients OR " +
           ":recipient MEMBER OF n.ccRecipients OR " +
           ":recipient MEMBER OF n.bccRecipients")
    List<NIS2EmailNotification> findNotificationsByRecipient(@Param("recipient") String recipient);

    // Templates by type
    @Query("SELECT n FROM NIS2EmailNotification n WHERE n.isTemplate = true AND n.notificationType = :notificationType")
    List<NIS2EmailNotification> findTemplatesByType(@Param("notificationType") NIS2EmailNotification.NotificationType notificationType);
} 