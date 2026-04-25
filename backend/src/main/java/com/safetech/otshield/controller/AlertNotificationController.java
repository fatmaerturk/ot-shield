package com.safetech.otshield.controller;

import com.safetech.otshield.dto.AlertNotificationDTO;
import com.safetech.otshield.dto.AlertNotificationDTO;
import com.safetech.otshield.mapper.AlertNotificationMapper;
import com.safetech.otshield.model.Alert;
import com.safetech.otshield.model.AlertNotification;
import com.safetech.otshield.repository.AlertNotificationRepository;
import com.safetech.otshield.repository.AlertRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * REST Controller for managing alert notifications
 * Provides CRUD operations and notification management capabilities
 */
@RestController
@RequestMapping("/api/alert-notifications")
@RequiredArgsConstructor
public class AlertNotificationController {

    private final AlertNotificationRepository alertNotificationRepository;
    private final AlertRepository alertRepository;
    private final AlertNotificationMapper alertNotificationMapper;

    /**
     * Get all notifications with pagination and sorting
     */
    @GetMapping
    public ResponseEntity<Page<AlertNotificationDTO>> getAllNotifications(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDir) {
        
        Sort sort = sortDir.equalsIgnoreCase("ASC") ? 
            Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        Pageable pageable = PageRequest.of(page, size, sort);
        
        Page<AlertNotification> notifications = alertNotificationRepository.findAll(pageable);
        Page<AlertNotificationDTO> notificationDtos = notifications.map(alertNotificationMapper::toDto);
        return ResponseEntity.ok(notificationDtos);
    }

    /**
     * Get notification by ID
     */
    @GetMapping("/{id}")
    public ResponseEntity<AlertNotificationDTO> getNotificationById(@PathVariable String id) {
        Optional<AlertNotification> notification = alertNotificationRepository.findById(id);
        return notification.map(alertNotificationMapper::toDto)
                          .map(ResponseEntity::ok)
                          .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Create a new notification
     */
    @PostMapping
    public ResponseEntity<AlertNotificationDTO> createNotification(@RequestBody AlertNotificationDTO notificationDto) {
        if (!alertRepository.existsById(notificationDto.getAlertId())) {
            return ResponseEntity.badRequest().build();
        }
        
        AlertNotification notification = alertNotificationMapper.toEntity(notificationDto);
        // Set the alert reference
        Alert alert = alertRepository.findById(notificationDto.getAlertId()).orElse(null);
        notification.setAlert(alert);
        
        AlertNotification savedNotification = alertNotificationRepository.save(notification);
        AlertNotificationDTO savedNotificationDto = alertNotificationMapper.toDto(savedNotification);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedNotificationDto);
    }

    /**
     * Update an existing notification
     */
    @PutMapping("/{id}")
    public ResponseEntity<AlertNotificationDTO> updateNotification(@PathVariable String id, @RequestBody AlertNotificationDTO notificationDto) {
        if (!alertNotificationRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        
        AlertNotification notification = alertNotificationMapper.toEntity(notificationDto);
        notification.setId(id);
        AlertNotification updatedNotification = alertNotificationRepository.save(notification);
        AlertNotificationDTO updatedNotificationDto = alertNotificationMapper.toDto(updatedNotification);
        return ResponseEntity.ok(updatedNotificationDto);
    }

    /**
     * Delete a notification
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteNotification(@PathVariable String id) {
        if (!alertNotificationRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        
        alertNotificationRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    /**
     * Get notifications by alert ID
     */
    @GetMapping("/alert/{alertId}")
    public ResponseEntity<List<AlertNotificationDTO>> getNotificationsByAlertId(@PathVariable String alertId) {
        List<AlertNotification> notifications = alertNotificationRepository.findByAlertId(alertId);
        List<AlertNotificationDTO> notificationDtos = notifications.stream()
                .map(alertNotificationMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(notificationDtos);
    }

    /**
     * Get notifications by status
     */
    @GetMapping("/status/{status}")
    public ResponseEntity<List<AlertNotificationDTO>> getNotificationsByStatus(@PathVariable AlertNotification.NotificationStatus status) {
        List<AlertNotification> notifications = alertNotificationRepository.findByStatus(status);
        List<AlertNotificationDTO> notificationDtos = notifications.stream()
                .map(alertNotificationMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(notificationDtos);
    }

    /**
     * Get pending notifications
     */
    @GetMapping("/pending")
    public ResponseEntity<List<AlertNotificationDTO>> getPendingNotifications() {
        List<AlertNotification> notifications = alertNotificationRepository.findPendingNotifications();
        List<AlertNotificationDTO> notificationDtos = notifications.stream()
                .map(alertNotificationMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(notificationDtos);
    }

    /**
     * Mark notification as sent
     */
    @PostMapping("/{id}/mark-sent")
    public ResponseEntity<AlertNotificationDTO> markAsSent(@PathVariable String id) {
        Optional<AlertNotification> notificationOpt = alertNotificationRepository.findById(id);
        if (notificationOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        AlertNotification notification = notificationOpt.get();
        notification.setStatus(AlertNotification.NotificationStatus.SENT);
        notification.setSentAt(LocalDateTime.now());
        
        AlertNotification updatedNotification = alertNotificationRepository.save(notification);
        AlertNotificationDTO updatedNotificationDto = alertNotificationMapper.toDto(updatedNotification);
        return ResponseEntity.ok(updatedNotificationDto);
    }

    /**
     * Mark notification as delivered
     */
    @PostMapping("/{id}/mark-delivered")
    public ResponseEntity<AlertNotificationDTO> markAsDelivered(@PathVariable String id) {
        Optional<AlertNotification> notificationOpt = alertNotificationRepository.findById(id);
        if (notificationOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        AlertNotification notification = notificationOpt.get();
        notification.setStatus(AlertNotification.NotificationStatus.DELIVERED);
        notification.setDeliveredAt(LocalDateTime.now());
        
        AlertNotification updatedNotification = alertNotificationRepository.save(notification);
        AlertNotificationDTO updatedNotificationDto = alertNotificationMapper.toDto(updatedNotification);
        return ResponseEntity.ok(updatedNotificationDto);
    }

    /**
     * Get notification statistics
     */
    @GetMapping("/statistics")
    public ResponseEntity<Map<String, Object>> getNotificationStatistics() {
        Map<String, Object> stats = Map.of(
            "totalNotifications", alertNotificationRepository.count(),
            "pendingNotifications", alertNotificationRepository.countByStatus(AlertNotification.NotificationStatus.PENDING),
            "sentNotifications", alertNotificationRepository.countByStatus(AlertNotification.NotificationStatus.SENT),
            "deliveredNotifications", alertNotificationRepository.countByStatus(AlertNotification.NotificationStatus.DELIVERED),
            "failedNotifications", alertNotificationRepository.countByStatus(AlertNotification.NotificationStatus.FAILED)
        );
        
        return ResponseEntity.ok(stats);
    }
} 