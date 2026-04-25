package com.safetech.otshield.controller;

import com.safetech.otshield.dto.AlertDTO;
import com.safetech.otshield.mapper.AlertMapper;
import com.safetech.otshield.model.Alert;
import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.AlertStatus;
import com.safetech.otshield.model.AlertType;
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
import java.util.ArrayList;

/**
 * REST Controller for managing security alerts
 * Provides CRUD operations and advanced filtering capabilities for alert management
 */
@RestController
@RequestMapping("/api/alerts")
@RequiredArgsConstructor
public class AlertsController {

    private final AlertRepository alertRepository;
    private final AlertMapper alertMapper;

    /**
     * Get all alerts with pagination and sorting
     * @param page Page number (default: 0)
     * @param size Page size (default: 20)
     * @param sortBy Sort field (default: createdAt)
     * @param sortDir Sort direction (default: DESC)
     * @return Paginated list of alert DTOs
     */
    @GetMapping
    public ResponseEntity<Page<AlertDTO>> getAllAlerts(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDir) {
        
        Sort sort = sortDir.equalsIgnoreCase("ASC") ? 
            Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        Pageable pageable = PageRequest.of(page, size, sort);
        
        Page<Alert> alerts = alertRepository.findAll(pageable);
        Page<AlertDTO> alertDtos = alerts.map(alertMapper::toDto);
        return ResponseEntity.ok(alertDtos);
    }

    /**
     * Get alert by ID
     * @param id Alert ID
     * @return Alert DTO details or 404 if not found
     */
    @GetMapping("/{id}")
    public ResponseEntity<AlertDTO> getAlertById(@PathVariable String id) {
        Optional<Alert> alert = alertRepository.findById(id);
        return alert.map(alertMapper::toDto)
                   .map(ResponseEntity::ok)
                   .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Create a new alert
     * @param alertDto Alert DTO data to create
     * @return Created alert DTO with generated ID
     */
    @PostMapping
    public ResponseEntity<AlertDTO> createAlert(@RequestBody AlertDTO alertDto) {
        Alert alert = alertMapper.toEntity(alertDto);
        
        // Set initial status if not provided
        if (alert.getStatus() == null) {
            alert.setStatus(AlertStatus.NEW);
        }
        
        Alert savedAlert = alertRepository.save(alert);
        AlertDTO savedAlertDto = alertMapper.toDto(savedAlert);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedAlertDto);
    }

    /**
     * Update an existing alert
     * @param id Alert ID
     * @param alertDto Updated alert DTO data
     * @return Updated alert DTO or 404 if not found
     */
    @PutMapping("/{id}")
    public ResponseEntity<AlertDTO> updateAlert(@PathVariable String id, @RequestBody AlertDTO alertDto) {
        if (!alertRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        
        Alert alert = alertMapper.toEntity(alertDto);
        alert.setId(id);
        Alert updatedAlert = alertRepository.save(alert);
        AlertDTO updatedAlertDto = alertMapper.toDto(updatedAlert);
        return ResponseEntity.ok(updatedAlertDto);
    }

    /**
     * Delete an alert
     * @param id Alert ID
     * @return 204 No Content on success
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteAlert(@PathVariable String id) {
        if (!alertRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        
        alertRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    /**
     * Get alerts by status
     * @param status Alert status to filter by
     * @param page Page number
     * @param size Page size
     * @return Paginated list of alert DTOs with specified status
     */
    @GetMapping("/status/{status}")
    public ResponseEntity<Page<AlertDTO>> getAlertsByStatus(
            @PathVariable AlertStatus status,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<Alert> alerts = alertRepository.findByStatus(status, pageable);
        Page<AlertDTO> alertDtos = alerts.map(alertMapper::toDto);
        return ResponseEntity.ok(alertDtos);
    }

    /**
     * Get alerts by severity
     * @param severity Alert severity to filter by
     * @param page Page number
     * @param size Page size
     * @return Paginated list of alert DTOs with specified severity
     */
    @GetMapping("/severity/{severity}")
    public ResponseEntity<Page<AlertDTO>> getAlertsBySeverity(
            @PathVariable AlertSeverity severity,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<Alert> alerts = alertRepository.findBySeverity(severity, pageable);
        Page<AlertDTO> alertDtos = alerts.map(alertMapper::toDto);
        return ResponseEntity.ok(alertDtos);
    }

    /**
     * Get alerts by type
     * @param type Alert type to filter by
     * @param page Page number
     * @param size Page size
     * @return Paginated list of alert DTOs with specified type
     */
    @GetMapping("/type/{type}")
    public ResponseEntity<Page<AlertDTO>> getAlertsByType(
            @PathVariable AlertType type,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<Alert> alerts = alertRepository.findByType(type, pageable);
        Page<AlertDTO> alertDtos = alerts.map(alertMapper::toDto);
        return ResponseEntity.ok(alertDtos);
    }

    /**
     * Get alerts by source
     * @param source Alert source to filter by
     * @return List of alert DTOs from specified source
     */
    @GetMapping("/source/{source}")
    public ResponseEntity<List<AlertDTO>> getAlertsBySource(@PathVariable String source) {
        List<Alert> alerts = alertRepository.findBySource(source);
        List<AlertDTO> alertDtos = alerts.stream()
                .map(alertMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(alertDtos);
    }

    /**
     * Get alerts by IP address (source or destination)
     * @param ip IP address to search for
     * @return List of alert DTOs involving the specified IP
     */
    @GetMapping("/ip/{ip}")
    public ResponseEntity<List<AlertDTO>> getAlertsByIpAddress(@PathVariable String ip) {
        List<Alert> alerts = alertRepository.findByIpAddress(ip);
        List<AlertDTO> alertDtos = alerts.stream()
                .map(alertMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(alertDtos);
    }

    /**
     * Get alerts by date range
     * @param startDate Start date (ISO format)
     * @param endDate End date (ISO format)
     * @return List of alert DTOs within the date range
     */
    @GetMapping("/date-range")
    public ResponseEntity<List<AlertDTO>> getAlertsByDateRange(
            @RequestParam String startDate,
            @RequestParam String endDate) {
        
        LocalDateTime start = LocalDateTime.parse(startDate);
        LocalDateTime end = LocalDateTime.parse(endDate);
        List<Alert> alerts = alertRepository.findByCreatedAtBetween(start, end);
        List<AlertDTO> alertDtos = alerts.stream()
                .map(alertMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(alertDtos);
    }

    /**
     * Get alerts assigned to a specific user
     * @param assignedTo User ID or username
     * @return List of alert DTOs assigned to the user
     */
    @GetMapping("/assigned/{assignedTo}")
    public ResponseEntity<List<AlertDTO>> getAlertsByAssignedTo(@PathVariable String assignedTo) {
        List<Alert> alerts = alertRepository.findByAssignedTo(assignedTo);
        List<AlertDTO> alertDtos = alerts.stream()
                .map(alertMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(alertDtos);
    }

    /**
     * Get unassigned alerts
     * @return List of alert DTOs that are not assigned to anyone
     */
    @GetMapping("/unassigned")
    public ResponseEntity<List<AlertDTO>> getUnassignedAlerts() {
        List<Alert> alerts = alertRepository.findByAssignedToIsNull();
        List<AlertDTO> alertDtos = alerts.stream()
                .map(alertMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(alertDtos);
    }

    /**
     * Search alerts by text in title, description, or source
     * @param searchTerm Search term
     * @param page Page number
     * @param size Page size
     * @return Paginated search results as DTOs
     */
    @GetMapping("/search")
    public ResponseEntity<Page<AlertDTO>> searchAlerts(
            @RequestParam String searchTerm,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<Alert> alerts = alertRepository.searchAlerts(searchTerm, pageable);
        Page<AlertDTO> alertDtos = alerts.map(alertMapper::toDto);
        return ResponseEntity.ok(alertDtos);
    }

    /**
     * Get alerts by tag
     * @param tag Tag to filter by
     * @return List of alert DTOs with the specified tag
     */
    @GetMapping("/tag/{tag}")
    public ResponseEntity<List<AlertDTO>> getAlertsByTag(@PathVariable String tag) {
        List<Alert> alerts = alertRepository.findByTag(tag);
        List<AlertDTO> alertDtos = alerts.stream()
                .map(alertMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(alertDtos);
    }

    /**
     * Get alerts with high risk scores
     * @param minScore Minimum risk score
     * @return List of alert DTOs with risk score above threshold
     */
    @GetMapping("/high-risk")
    public ResponseEntity<List<AlertDTO>> getHighRiskAlerts(
            @RequestParam(defaultValue = "7") Integer minScore) {
        List<Alert> alerts = alertRepository.findByRiskScoreGreaterThan(minScore);
        List<AlertDTO> alertDtos = alerts.stream()
                .map(alertMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(alertDtos);
    }

    /**
     * Assign an alert to a user
     * @param id Alert ID
     * @param request Assignment request containing assignedTo and assignedBy
     * @return Updated alert DTO
     */
    @PostMapping("/{id}/assign")
    public ResponseEntity<AlertDTO> assignAlert(
            @PathVariable String id,
            @RequestBody Map<String, String> request) {
        
        Optional<Alert> alertOpt = alertRepository.findById(id);
        if (alertOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        Alert alert = alertOpt.get();
        alert.setAssignedTo(request.get("assignedTo"));
        alert.setAssignedBy(request.get("assignedBy"));
        
        Alert updatedAlert = alertRepository.save(alert);
        AlertDTO updatedAlertDto = alertMapper.toDto(updatedAlert);
        return ResponseEntity.ok(updatedAlertDto);
    }

    /**
     * Acknowledge an alert
     * @param id Alert ID
     * @param request Acknowledgment request containing acknowledgedBy
     * @return Updated alert DTO
     */
    @PostMapping("/{id}/acknowledge")
    public ResponseEntity<AlertDTO> acknowledgeAlert(
            @PathVariable String id,
            @RequestBody Map<String, String> request) {
        
        Optional<Alert> alertOpt = alertRepository.findById(id);
        if (alertOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        Alert alert = alertOpt.get();
        alert.setAcknowledged(true);
        alert.setAcknowledgedBy(request.get("acknowledgedBy"));
        alert.setAcknowledgedAt(LocalDateTime.now());
        alert.setStatus(AlertStatus.ACKNOWLEDGED);
        
        Alert updatedAlert = alertRepository.save(alert);
        AlertDTO updatedAlertDto = alertMapper.toDto(updatedAlert);
        return ResponseEntity.ok(updatedAlertDto);
    }

    /**
     * Mark alert as false positive
     * @param id Alert ID
     * @param request Request containing markedBy
     * @return Updated alert DTO
     */
    @PostMapping("/{id}/false-positive")
    public ResponseEntity<AlertDTO> markAsFalsePositive(
            @PathVariable String id,
            @RequestBody Map<String, String> request) {
        
        Optional<Alert> alertOpt = alertRepository.findById(id);
        if (alertOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        Alert alert = alertOpt.get();
        alert.setFalsePositive(true);
        alert.setStatus(AlertStatus.FALSE_POSITIVE);
        alert.setAssignedBy(request.get("markedBy"));
        
        Alert updatedAlert = alertRepository.save(alert);
        AlertDTO updatedAlertDto = alertMapper.toDto(updatedAlert);
        return ResponseEntity.ok(updatedAlertDto);
    }

    /**
     * Resolve an alert
     * @param id Alert ID
     * @param request Resolution request containing resolvedBy and mitigationNotes
     * @return Updated alert DTO
     */
    @PostMapping("/{id}/resolve")
    public ResponseEntity<AlertDTO> resolveAlert(
            @PathVariable String id,
            @RequestBody Map<String, String> request) {
        
        Optional<Alert> alertOpt = alertRepository.findById(id);
        if (alertOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        Alert alert = alertOpt.get();
        alert.setStatus(AlertStatus.RESOLVED);
        alert.setResolvedAt(LocalDateTime.now());
        alert.setMitigationNotes(request.get("mitigationNotes"));
        alert.setAssignedBy(request.get("resolvedBy"));
        
        Alert updatedAlert = alertRepository.save(alert);
        AlertDTO updatedAlertDto = alertMapper.toDto(updatedAlert);
        return ResponseEntity.ok(updatedAlertDto);
    }

    /**
     * Get alert statistics
     * @return Map containing various alert statistics
     */
    @GetMapping("/statistics")
    public ResponseEntity<Map<String, Object>> getAlertStatistics() {
        Map<String, Object> stats = Map.of(
            "totalAlerts", alertRepository.count(),
            "newAlerts", alertRepository.countByStatus(AlertStatus.NEW),
            "acknowledgedAlerts", alertRepository.countByStatus(AlertStatus.ACKNOWLEDGED),
            "resolvedAlerts", alertRepository.countByStatus(AlertStatus.RESOLVED),
            "criticalAlerts", alertRepository.countBySeverity(AlertSeverity.CRITICAL),
            "highAlerts", alertRepository.countBySeverity(AlertSeverity.HIGH),
            "unassignedAlerts", alertRepository.countByAssignedTo(null),
            "falsePositives", alertRepository.countByFalsePositive(true)
        );
        
        return ResponseEntity.ok(stats);
    }

    /**
     * Get recent alerts (last 24 hours)
     * @return List of alert DTOs created in the last 24 hours
     */
    @GetMapping("/recent")
    public ResponseEntity<List<AlertDTO>> getRecentAlerts() {
        LocalDateTime yesterday = LocalDateTime.now().minusHours(24);
        List<Alert> alerts = alertRepository.findByCreatedAtAfter(yesterday);
        List<AlertDTO> alertDtos = alerts.stream()
                .map(alertMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(alertDtos);
    }

    /**
     * Create sample alerts for testing purposes
     * @return List of created sample alert DTOs
     */
    @PostMapping("/create-sample")
    public ResponseEntity<List<AlertDTO>> createSampleAlerts() {
        try {
            List<Alert> sampleAlerts = new ArrayList<>();
            
            // Sample Alert 1: Anomaly
            Alert anomalyAlert = Alert.builder()
                .title("Unusual Network Activity Detected")
                .description("Suspicious network traffic pattern detected from IP 192.168.1.100")
                .severity(AlertSeverity.HIGH)
                .status(AlertStatus.NEW)
                .type(AlertType.ANOMALY)
                .source("Network Monitor")
                .sourceIp("192.168.1.100")
                .destinationIp("10.0.0.1")
                .sourcePort(443)
                .destinationPort(80)
                .protocol("TCP")
                .createdAt(LocalDateTime.now())
                .updatedAt(LocalDateTime.now())
                .build();
            
            // Sample Alert 2: Threat Intelligence
            Alert threatAlert = Alert.builder()
                .title("Known Malicious IP Detected")
                .description("IP address 185.220.101.45 matches known threat intelligence database")
                .severity(AlertSeverity.CRITICAL)
                .status(AlertStatus.NEW)
                .type(AlertType.THREAT_INTELLIGENCE)
                .source("Threat Intel Feed")
                .sourceIp("185.220.101.45")
                .destinationIp("192.168.1.50")
                .sourcePort(22)
                .destinationPort(22)
                .protocol("SSH")
                .createdAt(LocalDateTime.now().minusMinutes(15))
                .updatedAt(LocalDateTime.now().minusMinutes(15))
                .build();
            
            // Sample Alert 3: Honeypot
            Alert honeypotAlert = Alert.builder()
                .title("Honeypot Interaction Detected")
                .description("Potential attacker interaction with honeypot system detected")
                .severity(AlertSeverity.MEDIUM)
                .status(AlertStatus.NEW)
                .type(AlertType.HONEYPOT)
                .source("Honeypot System")
                .sourceIp("203.0.113.10")
                .destinationIp("192.168.1.200")
                .sourcePort(80)
                .destinationPort(8080)
                .protocol("HTTP")
                .createdAt(LocalDateTime.now().minusMinutes(30))
                .updatedAt(LocalDateTime.now().minusMinutes(30))
                .build();
            
            // Sample Alert 4: IOA (Indicator of Attack)
            Alert ioaAlert = Alert.builder()
                .title("Suspicious File Download Pattern")
                .description("Multiple executable files downloaded from suspicious domain")
                .severity(AlertSeverity.HIGH)
                .status(AlertStatus.NEW)
                .type(AlertType.IOA)
                .source("File Monitor")
                .sourceIp("192.168.1.75")
                .destinationIp("malicious-domain.com")
                .sourcePort(443)
                .destinationPort(443)
                .protocol("HTTPS")
                .createdAt(LocalDateTime.now().minusMinutes(45))
                .updatedAt(LocalDateTime.now().minusMinutes(45))
                .build();
            
            sampleAlerts.add(anomalyAlert);
            sampleAlerts.add(threatAlert);
            sampleAlerts.add(honeypotAlert);
            sampleAlerts.add(ioaAlert);
            
            // Save all sample alerts
            List<Alert> savedAlerts = alertRepository.saveAll(sampleAlerts);
            
            // Convert to DTOs
            List<AlertDTO> alertDtos = savedAlerts.stream()
                .map(alertMapper::toDto)
                .collect(Collectors.toList());
            
            return ResponseEntity.status(HttpStatus.CREATED).body(alertDtos);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}