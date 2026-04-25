package com.safetech.otshield.repository;

import com.safetech.otshield.model.Alert;
import com.safetech.otshield.model.AlertNotification;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface AlertNotificationRepository extends JpaRepository<AlertNotification, String> {
    
    // Basic finders
    List<AlertNotification> findByAlert(Alert alert);
    List<AlertNotification> findByAlertId(String alertId);
    Page<AlertNotification> findByAlertId(String alertId, Pageable pageable);
    
    // Status-based queries
    List<AlertNotification> findByStatus(AlertNotification.NotificationStatus status);
    List<AlertNotification> findByStatusIn(List<AlertNotification.NotificationStatus> statuses);
    
    // Type-based queries
    List<AlertNotification> findByNotificationType(AlertNotification.NotificationType notificationType);
    List<AlertNotification> findByNotificationTypeIn(List<AlertNotification.NotificationType> types);
    
    // Recipient queries
    List<AlertNotification> findByRecipient(String recipient);
    List<AlertNotification> findByRecipientAndAlertId(String recipient, String alertId);
    
    // Time-based queries
    List<AlertNotification> findByCreatedAtBetween(LocalDateTime startDate, LocalDateTime endDate);
    List<AlertNotification> findByCreatedAtAfter(LocalDateTime date);
    List<AlertNotification> findByCreatedAtBefore(LocalDateTime date);
    List<AlertNotification> findBySentAtBetween(LocalDateTime startDate, LocalDateTime endDate);
    List<AlertNotification> findByDeliveredAtBetween(LocalDateTime startDate, LocalDateTime endDate);
    List<AlertNotification> findByReadAtBetween(LocalDateTime startDate, LocalDateTime endDate);
    
    // Retry queries
    List<AlertNotification> findByRetryCountGreaterThan(Integer retryCount);
    List<AlertNotification> findByRetryCountLessThan(Integer retryCount);
    List<AlertNotification> findByRetryCountBetween(Integer minRetries, Integer maxRetries);
    
    // Error queries
    List<AlertNotification> findByErrorMessageIsNotNull();
    List<AlertNotification> findByErrorMessageIsNull();
    
    // Complex queries
    @Query("SELECT n FROM AlertNotification n WHERE n.alert.id = :alertId AND n.status = :status")
    List<AlertNotification> findByAlertIdAndStatus(@Param("alertId") String alertId, 
                                                  @Param("status") AlertNotification.NotificationStatus status);
    
    @Query("SELECT n FROM AlertNotification n WHERE n.alert.id = :alertId AND n.notificationType = :type")
    List<AlertNotification> findByAlertIdAndType(@Param("alertId") String alertId, 
                                                @Param("type") AlertNotification.NotificationType type);
    
    @Query("SELECT n FROM AlertNotification n WHERE n.recipient = :recipient AND n.status = :status")
    List<AlertNotification> findByRecipientAndStatus(@Param("recipient") String recipient, 
                                                    @Param("status") AlertNotification.NotificationStatus status);
    
    @Query("SELECT n FROM AlertNotification n WHERE n.createdAt >= :startDate AND n.notificationType = :type")
    List<AlertNotification> findByCreatedAtAfterAndType(@Param("startDate") LocalDateTime startDate, 
                                                       @Param("type") AlertNotification.NotificationType type);
    
    // Pending notifications
    @Query("SELECT n FROM AlertNotification n WHERE n.status = 'PENDING' AND n.retryCount < n.maxRetries")
    List<AlertNotification> findPendingNotifications();
    
    @Query("SELECT n FROM AlertNotification n WHERE n.status = 'PENDING' AND n.notificationType = :type")
    List<AlertNotification> findPendingNotificationsByType(@Param("type") AlertNotification.NotificationType type);
    
    // Failed notifications
    @Query("SELECT n FROM AlertNotification n WHERE n.status = 'FAILED' AND n.retryCount < n.maxRetries")
    List<AlertNotification> findFailedNotificationsForRetry();
    
    // Search queries
    @Query("SELECT n FROM AlertNotification n WHERE LOWER(n.subject) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
           "OR LOWER(n.message) LIKE LOWER(CONCAT('%', :searchTerm, '%')) " +
           "OR LOWER(n.recipient) LIKE LOWER(CONCAT('%', :searchTerm, '%'))")
    Page<AlertNotification> searchNotifications(@Param("searchTerm") String searchTerm, Pageable pageable);
    
    // Count queries
    long countByAlert(Alert alert);
    long countByAlertId(String alertId);
    long countByStatus(AlertNotification.NotificationStatus status);
    long countByNotificationType(AlertNotification.NotificationType type);
    long countByRecipient(String recipient);
    long countByRetryCountGreaterThan(Integer retryCount);
    
    @Query("SELECT COUNT(n) FROM AlertNotification n WHERE n.alert.id = :alertId AND n.status = :status")
    long countByAlertIdAndStatus(@Param("alertId") String alertId, 
                                @Param("status") AlertNotification.NotificationStatus status);
    
    @Query("SELECT COUNT(n) FROM AlertNotification n WHERE n.createdAt >= :startDate")
    long countByCreatedAtAfter(@Param("startDate") LocalDateTime startDate);
    
    @Query("SELECT COUNT(n) FROM AlertNotification n WHERE n.createdAt BETWEEN :startDate AND :endDate")
    long countByCreatedAtBetween(@Param("startDate") LocalDateTime startDate, 
                                @Param("endDate") LocalDateTime endDate);
    
    // Delivery statistics
    @Query("SELECT COUNT(n) FROM AlertNotification n WHERE n.status = 'DELIVERED' AND n.deliveredAt >= :startDate")
    long countDeliveredNotificationsAfter(@Param("startDate") LocalDateTime startDate);
    
    @Query("SELECT COUNT(n) FROM AlertNotification n WHERE n.status = 'READ' AND n.readAt >= :startDate")
    long countReadNotificationsAfter(@Param("startDate") LocalDateTime startDate);
    
    // Channel configuration queries
    @Query("SELECT n FROM AlertNotification n WHERE n.channelConfig LIKE %:config%")
    List<AlertNotification> findByChannelConfigContaining(@Param("config") String config);
    
    // Notifications by time range and type
    @Query("SELECT n FROM AlertNotification n WHERE n.createdAt BETWEEN :startDate AND :endDate " +
           "AND n.notificationType = :type ORDER BY n.createdAt DESC")
    List<AlertNotification> findByDateRangeAndType(@Param("startDate") LocalDateTime startDate, 
                                                  @Param("endDate") LocalDateTime endDate, 
                                                  @Param("type") AlertNotification.NotificationType type);
} 