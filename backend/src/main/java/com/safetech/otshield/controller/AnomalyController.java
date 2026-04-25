package com.safetech.otshield.controller;

import com.safetech.otshield.dto.AnomalyDTO;
import com.safetech.otshield.model.Anomaly;
import com.safetech.otshield.service.AnomalyService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/anomalies")
@RequiredArgsConstructor
@Slf4j
public class AnomalyController {
    private final AnomalyService anomalyService;

    // CRUD Operations
    @PostMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<AnomalyDTO> createAnomaly(@RequestBody AnomalyDTO anomalyDto) {
        log.info("Creating new anomaly: {}", anomalyDto.getTitle());
        AnomalyDTO createdAnomaly = anomalyService.createAnomaly(anomalyDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdAnomaly);
    }

    @GetMapping("/{id}")
    public ResponseEntity<AnomalyDTO> getAnomalyById(@PathVariable String id) {
        log.debug("Fetching anomaly by ID: {}", id);
        Optional<AnomalyDTO> anomaly = anomalyService.getAnomalyById(id);
        return anomaly.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping
    public ResponseEntity<Page<AnomalyDTO>> getAllAnomalies(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "detectedAt") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir) {
        log.debug("Fetching all anomalies with pagination");
        Page<AnomalyDTO> anomalies = anomalyService.getAnomaliesWithPagination(page, size, sortBy, sortDir);
        return ResponseEntity.ok(anomalies);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<AnomalyDTO> updateAnomaly(@PathVariable String id, @RequestBody AnomalyDTO anomalyDto) {
        log.info("Updating anomaly with ID: {}", id);
        try {
            AnomalyDTO updatedAnomaly = anomalyService.updateAnomaly(id, anomalyDto);
            return ResponseEntity.ok(updatedAnomaly);
        } catch (RuntimeException e) {
            log.error("Error updating anomaly: {}", e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteAnomaly(@PathVariable String id) {
        log.info("Deleting anomaly with ID: {}", id);
        try {
            anomalyService.deleteAnomaly(id);
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            log.error("Error deleting anomaly: {}", e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    // Status Management Endpoints
    @PostMapping("/{id}/acknowledge")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<AnomalyDTO> acknowledgeAnomaly(@PathVariable String id) {
        log.info("Acknowledging anomaly with ID: {}", id);
        try {
            AnomalyDTO acknowledgedAnomaly = anomalyService.acknowledgeAnomaly(id);
            return ResponseEntity.ok(acknowledgedAnomaly);
        } catch (RuntimeException e) {
            log.error("Error acknowledging anomaly: {}", e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/{id}/escalate")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<AnomalyDTO> escalateAnomaly(@PathVariable String id) {
        log.info("Escalating anomaly with ID: {}", id);
        try {
            AnomalyDTO escalatedAnomaly = anomalyService.escalateAnomaly(id);
            return ResponseEntity.ok(escalatedAnomaly);
        } catch (RuntimeException e) {
            log.error("Error escalating anomaly: {}", e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/{id}/resolve")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<AnomalyDTO> resolveAnomaly(
            @PathVariable String id,
            @RequestParam String resolutionNotes) {
        log.info("Resolving anomaly with ID: {}", id);
        try {
            AnomalyDTO resolvedAnomaly = anomalyService.resolveAnomaly(id, resolutionNotes);
            return ResponseEntity.ok(resolvedAnomaly);
        } catch (RuntimeException e) {
            log.error("Error resolving anomaly: {}", e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    @PostMapping("/{id}/false-positive")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<AnomalyDTO> markAsFalsePositive(
            @PathVariable String id,
            @RequestParam String reason) {
        log.info("Marking anomaly as false positive with ID: {}", id);
        try {
            AnomalyDTO falsePositiveAnomaly = anomalyService.markAsFalsePositive(id, reason);
            return ResponseEntity.ok(falsePositiveAnomaly);
        } catch (RuntimeException e) {
            log.error("Error marking anomaly as false positive: {}", e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    // Search and Filter Endpoints
    @GetMapping("/search")
    public ResponseEntity<Page<AnomalyDTO>> searchAnomalies(
            @RequestParam(required = false) String title,
            @RequestParam(required = false) String sourceIp,
            @RequestParam(required = false) String destinationIp,
            @RequestParam(required = false) String protocol,
            @RequestParam(required = false) String assetType,
            @RequestParam(required = false) String purdueLevel,
            @RequestParam(required = false) Anomaly.AnomalySeverity severity,
            @RequestParam(required = false) Anomaly.AnomalyStatus status,
            @RequestParam(required = false) Anomaly.AnomalyType anomalyType,
            @RequestParam(required = false) Boolean isActive,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        log.debug("Searching anomalies with filters");
        Page<AnomalyDTO> anomalies = anomalyService.searchAnomalies(
                title, sourceIp, destinationIp, protocol, assetType, purdueLevel,
                severity, status, anomalyType, isActive, page, size);
        return ResponseEntity.ok(anomalies);
    }

    @GetMapping("/status/{status}")
    public ResponseEntity<List<AnomalyDTO>> getAnomaliesByStatus(@PathVariable Anomaly.AnomalyStatus status) {
        log.debug("Fetching anomalies by status: {}", status);
        List<AnomalyDTO> anomalies = anomalyService.getAnomaliesByStatus(status);
        return ResponseEntity.ok(anomalies);
    }

    @GetMapping("/severity/{severity}")
    public ResponseEntity<List<AnomalyDTO>> getAnomaliesBySeverity(@PathVariable Anomaly.AnomalySeverity severity) {
        log.debug("Fetching anomalies by severity: {}", severity);
        List<AnomalyDTO> anomalies = anomalyService.getAnomaliesBySeverity(severity);
        return ResponseEntity.ok(anomalies);
    }

    @GetMapping("/type/{type}")
    public ResponseEntity<List<AnomalyDTO>> getAnomaliesByType(@PathVariable Anomaly.AnomalyType type) {
        log.debug("Fetching anomalies by type: {}", type);
        List<AnomalyDTO> anomalies = anomalyService.getAnomaliesByType(type);
        return ResponseEntity.ok(anomalies);
    }

    @GetMapping("/date-range")
    public ResponseEntity<List<AnomalyDTO>> getAnomaliesByDateRange(
            @RequestParam String startDate,
            @RequestParam String endDate) {
        log.debug("Fetching anomalies by date range: {} to {}", startDate, endDate);
        LocalDateTime start = LocalDateTime.parse(startDate);
        LocalDateTime end = LocalDateTime.parse(endDate);
        List<AnomalyDTO> anomalies = anomalyService.getAnomaliesByDateRange(start, end);
        return ResponseEntity.ok(anomalies);
    }

    // Recent and Special Queries
    @GetMapping("/recent")
    public ResponseEntity<List<AnomalyDTO>> getRecentAnomalies(
            @RequestParam(defaultValue = "10") int limit) {
        log.debug("Fetching recent anomalies with limit: {}", limit);
        List<AnomalyDTO> anomalies = anomalyService.getRecentAnomalies(limit);
        return ResponseEntity.ok(anomalies);
    }

    @GetMapping("/unresolved")
    public ResponseEntity<List<AnomalyDTO>> getUnresolvedAnomalies(
            @RequestParam(defaultValue = "10") int limit) {
        log.debug("Fetching unresolved anomalies with limit: {}", limit);
        List<AnomalyDTO> anomalies = anomalyService.getUnresolvedAnomalies(limit);
        return ResponseEntity.ok(anomalies);
    }

    @GetMapping("/escalated")
    public ResponseEntity<List<AnomalyDTO>> getEscalatedAnomalies(
            @RequestParam(defaultValue = "10") int limit) {
        log.debug("Fetching escalated anomalies with limit: {}", limit);
        List<AnomalyDTO> anomalies = anomalyService.getEscalatedAnomalies(limit);
        return ResponseEntity.ok(anomalies);
    }

    @GetMapping("/top-risk")
    public ResponseEntity<List<AnomalyDTO>> getTopAnomaliesByRiskScore(
            @RequestParam(defaultValue = "10") int limit,
            @RequestParam(defaultValue = "2024-01-01T00:00:00") String since) {
        log.debug("Fetching top anomalies by risk score with limit: {}", limit);
        LocalDateTime sinceDate = LocalDateTime.parse(since);
        List<AnomalyDTO> anomalies = anomalyService.getTopAnomaliesByRiskScore(limit, sinceDate);
        return ResponseEntity.ok(anomalies);
    }

    @GetMapping("/asset")
    public ResponseEntity<List<AnomalyDTO>> getAnomaliesByAsset(
            @RequestParam(required = false) String hostname,
            @RequestParam(required = false) String ip) {
        log.debug("Fetching anomalies by asset: hostname={}, ip={}", hostname, ip);
        List<AnomalyDTO> anomalies = anomalyService.getAnomaliesByAsset(hostname, ip);
        return ResponseEntity.ok(anomalies);
    }

    // Statistics and Analytics Endpoints
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Long>> getAnomalyStatistics() {
        log.debug("Fetching anomaly statistics");
        Map<String, Long> stats = anomalyService.getAnomalyStatistics();
        return ResponseEntity.ok(stats);
    }

    @GetMapping("/stats/by-type")
    public ResponseEntity<Map<String, Long>> getAnomalyCountsByType() {
        log.debug("Fetching anomaly counts by type");
        Map<String, Long> counts = anomalyService.getAnomalyCountsByType();
        return ResponseEntity.ok(counts);
    }

    @GetMapping("/stats/by-severity")
    public ResponseEntity<Map<String, Long>> getAnomalyCountsBySeverity() {
        log.debug("Fetching anomaly counts by severity");
        Map<String, Long> counts = anomalyService.getAnomalyCountsBySeverity();
        return ResponseEntity.ok(counts);
    }

    @GetMapping("/stats/by-status")
    public ResponseEntity<Map<String, Long>> getAnomalyCountsByStatus() {
        log.debug("Fetching anomaly counts by status");
        Map<String, Long> counts = anomalyService.getAnomalyCountsByStatus();
        return ResponseEntity.ok(counts);
    }

    @GetMapping("/stats/count-by-date-range")
    public ResponseEntity<Long> getAnomalyCountByDateRange(
            @RequestParam String startDate,
            @RequestParam String endDate) {
        log.debug("Fetching anomaly count by date range: {} to {}", startDate, endDate);
        LocalDateTime start = LocalDateTime.parse(startDate);
        LocalDateTime end = LocalDateTime.parse(endDate);
        Long count = anomalyService.getAnomalyCountByDateRange(start, end);
        return ResponseEntity.ok(count);
    }

    // Bulk Operations
    @PostMapping("/bulk/update-status")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<List<AnomalyDTO>> bulkUpdateStatus(
            @RequestParam List<String> anomalyIds,
            @RequestParam Anomaly.AnomalyStatus status) {
        log.info("Bulk updating status for {} anomalies to: {}", anomalyIds.size(), status);
        List<AnomalyDTO> updatedAnomalies = anomalyService.bulkUpdateStatus(anomalyIds, status);
        return ResponseEntity.ok(updatedAnomalies);
    }

    @PostMapping("/bulk/assign")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<List<AnomalyDTO>> bulkAssign(
            @RequestParam List<String> anomalyIds,
            @RequestParam String assignedTo) {
        log.info("Bulk assigning {} anomalies to: {}", anomalyIds.size(), assignedTo);
        List<AnomalyDTO> assignedAnomalies = anomalyService.bulkAssign(anomalyIds, assignedTo);
        return ResponseEntity.ok(assignedAnomalies);
    }

    // Health Check
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> healthCheck() {
        log.debug("Anomaly service health check");
        Map<String, String> health = Map.of(
                "status", "UP",
                "service", "AnomalyService",
                "timestamp", LocalDateTime.now().toString()
        );
        return ResponseEntity.ok(health);
    }
} 