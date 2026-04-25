package com.safetech.otshield.service;

import com.safetech.otshield.dto.AnomalyDTO;
import com.safetech.otshield.mapper.AnomalyMapper;
import com.safetech.otshield.model.Anomaly;
import com.safetech.otshield.repository.AnomalyRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.HashMap;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AnomalyService {
    private final AnomalyRepository anomalyRepository;
    private final AnomalyMapper anomalyMapper;

    // CRUD Operations
    public AnomalyDTO createAnomaly(AnomalyDTO anomalyDto) {
        log.info("Creating new anomaly: {}", anomalyDto.getTitle());
        
        Anomaly anomaly = anomalyMapper.toEntity(anomalyDto);
        setAuditFields(anomaly, true);
        
        Anomaly savedAnomaly = anomalyRepository.save(anomaly);
        log.info("Anomaly created with ID: {}", savedAnomaly.getId());
        
        return anomalyMapper.toDto(savedAnomaly);
    }

    public Optional<AnomalyDTO> getAnomalyById(String id) {
        log.debug("Fetching anomaly by ID: {}", id);
        return anomalyRepository.findById(id)
                .map(anomalyMapper::toDto);
    }

    public List<AnomalyDTO> getAllAnomalies() {
        log.debug("Fetching all anomalies");
        return anomalyRepository.findAll()
                .stream()
                .map(anomalyMapper::toDto)
                .collect(Collectors.toList());
    }

    public Page<AnomalyDTO> getAnomaliesWithPagination(int page, int size, String sortBy, String sortDir) {
        log.debug("Fetching anomalies with pagination: page={}, size={}, sortBy={}, sortDir={}", page, size, sortBy, sortDir);
        
        Sort sort = sortDir.equalsIgnoreCase(Sort.Direction.ASC.name()) ? 
                Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        
        Pageable pageable = PageRequest.of(page, size, sort);
        return anomalyRepository.findAll(pageable)
                .map(anomalyMapper::toDto);
    }

    public AnomalyDTO updateAnomaly(String id, AnomalyDTO anomalyDto) {
        log.info("Updating anomaly with ID: {}", id);
        
        Optional<Anomaly> existingAnomaly = anomalyRepository.findById(id);
        if (existingAnomaly.isEmpty()) {
            throw new RuntimeException("Anomaly not found with ID: " + id);
        }

        Anomaly anomaly = existingAnomaly.get();
        updateAnomalyFields(anomaly, anomalyDto);
        setAuditFields(anomaly, false);
        
        Anomaly updatedAnomaly = anomalyRepository.save(anomaly);
        log.info("Anomaly updated successfully: {}", id);
        
        return anomalyMapper.toDto(updatedAnomaly);
    }

    public void deleteAnomaly(String id) {
        log.info("Deleting anomaly with ID: {}", id);
        anomalyRepository.deleteById(id);
        log.info("Anomaly deleted successfully: {}", id);
    }

    // Status Management
    public AnomalyDTO acknowledgeAnomaly(String id) {
        log.info("Acknowledging anomaly with ID: {}", id);
        
        Optional<Anomaly> anomaly = anomalyRepository.findById(id);
        if (anomaly.isEmpty()) {
            throw new RuntimeException("Anomaly not found with ID: " + id);
        }

        Anomaly anomalyEntity = anomaly.get();
        anomalyEntity.setStatus(Anomaly.AnomalyStatus.ACKNOWLEDGED);
        anomalyEntity.setIsAcknowledged(true);
        anomalyEntity.setAcknowledgedAt(LocalDateTime.now());
        setAuditFields(anomalyEntity, false);
        
        Anomaly savedAnomaly = anomalyRepository.save(anomalyEntity);
        log.info("Anomaly acknowledged successfully: {}", id);
        
        return anomalyMapper.toDto(savedAnomaly);
    }

    public AnomalyDTO escalateAnomaly(String id) {
        log.info("Escalating anomaly with ID: {}", id);
        
        Optional<Anomaly> anomaly = anomalyRepository.findById(id);
        if (anomaly.isEmpty()) {
            throw new RuntimeException("Anomaly not found with ID: " + id);
        }

        Anomaly anomalyEntity = anomaly.get();
        anomalyEntity.setStatus(Anomaly.AnomalyStatus.ESCALATED);
        anomalyEntity.setIsEscalated(true);
        anomalyEntity.setEscalatedAt(LocalDateTime.now());
        setAuditFields(anomalyEntity, false);
        
        Anomaly savedAnomaly = anomalyRepository.save(anomalyEntity);
        log.info("Anomaly escalated successfully: {}", id);
        
        return anomalyMapper.toDto(savedAnomaly);
    }

    public AnomalyDTO resolveAnomaly(String id, String resolutionNotes) {
        log.info("Resolving anomaly with ID: {}", id);
        
        Optional<Anomaly> anomaly = anomalyRepository.findById(id);
        if (anomaly.isEmpty()) {
            throw new RuntimeException("Anomaly not found with ID: " + id);
        }

        Anomaly anomalyEntity = anomaly.get();
        anomalyEntity.setStatus(Anomaly.AnomalyStatus.RESOLVED);
        anomalyEntity.setIsResolved(true);
        anomalyEntity.setResolvedAt(LocalDateTime.now());
        anomalyEntity.setNotes(resolutionNotes);
        setAuditFields(anomalyEntity, false);
        
        Anomaly savedAnomaly = anomalyRepository.save(anomalyEntity);
        log.info("Anomaly resolved successfully: {}", id);
        
        return anomalyMapper.toDto(savedAnomaly);
    }

    public AnomalyDTO markAsFalsePositive(String id, String reason) {
        log.info("Marking anomaly as false positive with ID: {}", id);
        
        Optional<Anomaly> anomaly = anomalyRepository.findById(id);
        if (anomaly.isEmpty()) {
            throw new RuntimeException("Anomaly not found with ID: " + id);
        }

        Anomaly anomalyEntity = anomaly.get();
        anomalyEntity.setStatus(Anomaly.AnomalyStatus.FALSE_POSITIVE);
        anomalyEntity.setIsFalsePositive(true);
        anomalyEntity.setNotes(reason);
        setAuditFields(anomalyEntity, false);
        
        Anomaly savedAnomaly = anomalyRepository.save(anomalyEntity);
        log.info("Anomaly marked as false positive successfully: {}", id);
        
        return anomalyMapper.toDto(savedAnomaly);
    }

    // Search and Filter Operations
    public Page<AnomalyDTO> searchAnomalies(String title, String sourceIp, String destinationIp, 
                                           String protocol, String assetType, String purdueLevel,
                                           Anomaly.AnomalySeverity severity, Anomaly.AnomalyStatus status,
                                           Anomaly.AnomalyType anomalyType, Boolean isActive, 
                                           int page, int size) {
        log.debug("Searching anomalies with filters");
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("detectedAt").descending());
        return anomalyRepository.findAnomaliesWithFilters(
                title, sourceIp, destinationIp, protocol, assetType, purdueLevel,
                severity, status, anomalyType, isActive, pageable
        ).map(anomalyMapper::toDto);
    }

    public List<AnomalyDTO> getAnomaliesByStatus(Anomaly.AnomalyStatus status) {
        log.debug("Fetching anomalies by status: {}", status);
        return anomalyRepository.findByStatus(status)
                .stream()
                .map(anomalyMapper::toDto)
                .collect(Collectors.toList());
    }

    public List<AnomalyDTO> getAnomaliesBySeverity(Anomaly.AnomalySeverity severity) {
        log.debug("Fetching anomalies by severity: {}", severity);
        return anomalyRepository.findBySeverity(severity)
                .stream()
                .map(anomalyMapper::toDto)
                .collect(Collectors.toList());
    }

    public List<AnomalyDTO> getAnomaliesByType(Anomaly.AnomalyType anomalyType) {
        log.debug("Fetching anomalies by type: {}", anomalyType);
        return anomalyRepository.findByAnomalyType(anomalyType)
                .stream()
                .map(anomalyMapper::toDto)
                .collect(Collectors.toList());
    }

    public List<AnomalyDTO> getAnomaliesByDateRange(LocalDateTime startDate, LocalDateTime endDate) {
        log.debug("Fetching anomalies by date range: {} to {}", startDate, endDate);
        return anomalyRepository.findByDetectedAtBetween(startDate, endDate)
                .stream()
                .map(anomalyMapper::toDto)
                .collect(Collectors.toList());
    }

    public List<AnomalyDTO> getRecentAnomalies(int limit) {
        log.debug("Fetching recent anomalies with limit: {}", limit);
        Pageable pageable = PageRequest.of(0, limit, Sort.by("detectedAt").descending());
        return anomalyRepository.findRecentAnomalies(pageable)
                .stream()
                .map(anomalyMapper::toDto)
                .collect(Collectors.toList());
    }

    public List<AnomalyDTO> getUnresolvedAnomalies(int limit) {
        log.debug("Fetching unresolved anomalies with limit: {}", limit);
        Pageable pageable = PageRequest.of(0, limit, Sort.by("detectedAt").descending());
        return anomalyRepository.findUnresolvedAnomalies(pageable)
                .stream()
                .map(anomalyMapper::toDto)
                .collect(Collectors.toList());
    }

    public List<AnomalyDTO> getEscalatedAnomalies(int limit) {
        log.debug("Fetching escalated anomalies with limit: {}", limit);
        Pageable pageable = PageRequest.of(0, limit, Sort.by("escalatedAt").descending());
        return anomalyRepository.findEscalatedAnomalies(pageable)
                .stream()
                .map(anomalyMapper::toDto)
                .collect(Collectors.toList());
    }

    public List<AnomalyDTO> getTopAnomaliesByRiskScore(int limit, LocalDateTime since) {
        log.debug("Fetching top anomalies by risk score with limit: {}", limit);
        Pageable pageable = PageRequest.of(0, limit);
        return anomalyRepository.findTopAnomaliesByRiskScore(since, pageable)
                .stream()
                .map(anomalyMapper::toDto)
                .collect(Collectors.toList());
    }

    public List<AnomalyDTO> getAnomaliesByAsset(String hostname, String ip) {
        log.debug("Fetching anomalies by asset: hostname={}, ip={}", hostname, ip);
        return anomalyRepository.findByAsset(hostname, ip)
                .stream()
                .map(anomalyMapper::toDto)
                .collect(Collectors.toList());
    }

    // Statistics and Analytics
    public Map<String, Long> getAnomalyStatistics() {
        log.debug("Calculating anomaly statistics");
        
        Map<String, Long> stats = new HashMap<>();
        stats.put("total", anomalyRepository.count());
        stats.put("detected", anomalyRepository.countByStatus(Anomaly.AnomalyStatus.DETECTED));
        stats.put("acknowledged", anomalyRepository.countByStatus(Anomaly.AnomalyStatus.ACKNOWLEDGED));
        stats.put("investigating", anomalyRepository.countByStatus(Anomaly.AnomalyStatus.INVESTIGATING));
        stats.put("escalated", anomalyRepository.countByStatus(Anomaly.AnomalyStatus.ESCALATED));
        stats.put("resolved", anomalyRepository.countByStatus(Anomaly.AnomalyStatus.RESOLVED));
        stats.put("falsePositive", anomalyRepository.countByStatus(Anomaly.AnomalyStatus.FALSE_POSITIVE));
        stats.put("critical", anomalyRepository.countBySeverity(Anomaly.AnomalySeverity.CRITICAL));
        stats.put("high", anomalyRepository.countBySeverity(Anomaly.AnomalySeverity.HIGH));
        stats.put("medium", anomalyRepository.countBySeverity(Anomaly.AnomalySeverity.MEDIUM));
        stats.put("low", anomalyRepository.countBySeverity(Anomaly.AnomalySeverity.LOW));
        stats.put("active", anomalyRepository.countByIsActive(true));
        
        return stats;
    }

    public Map<String, Long> getAnomalyCountsByType() {
        log.debug("Calculating anomaly counts by type");
        
        return anomalyRepository.findAll()
                .stream()
                .collect(Collectors.groupingBy(
                        anomaly -> anomaly.getAnomalyType().getDisplayName(),
                        Collectors.counting()
                ));
    }

    public Map<String, Long> getAnomalyCountsBySeverity() {
        log.debug("Calculating anomaly counts by severity");
        
        return anomalyRepository.findAll()
                .stream()
                .collect(Collectors.groupingBy(
                        anomaly -> anomaly.getSeverity().getDisplayName(),
                        Collectors.counting()
                ));
    }

    public Map<String, Long> getAnomalyCountsByStatus() {
        log.debug("Calculating anomaly counts by status");
        
        return anomalyRepository.findAll()
                .stream()
                .collect(Collectors.groupingBy(
                        anomaly -> anomaly.getStatus().getDisplayName(),
                        Collectors.counting()
                ));
    }

    public Long getAnomalyCountByDateRange(LocalDateTime startDate, LocalDateTime endDate) {
        log.debug("Calculating anomaly count by date range: {} to {}", startDate, endDate);
        return anomalyRepository.countByDetectedAtBetween(startDate, endDate);
    }

    // Bulk Operations
    public List<AnomalyDTO> bulkUpdateStatus(List<String> anomalyIds, Anomaly.AnomalyStatus status) {
        log.info("Bulk updating status for {} anomalies to: {}", anomalyIds.size(), status);
        
        List<Anomaly> anomalies = anomalyRepository.findAllById(anomalyIds);
        anomalies.forEach(anomaly -> {
            anomaly.setStatus(status);
            setAuditFields(anomaly, false);
        });
        
        List<Anomaly> savedAnomalies = anomalyRepository.saveAll(anomalies);
        log.info("Bulk status update completed successfully");
        
        return savedAnomalies.stream()
                .map(anomalyMapper::toDto)
                .collect(Collectors.toList());
    }

    public List<AnomalyDTO> bulkAssign(List<String> anomalyIds, String assignedTo) {
        log.info("Bulk assigning {} anomalies to: {}", anomalyIds.size(), assignedTo);
        
        List<Anomaly> anomalies = anomalyRepository.findAllById(anomalyIds);
        anomalies.forEach(anomaly -> {
            anomaly.setAssignedTo(assignedTo);
            setAuditFields(anomaly, false);
        });
        
        List<Anomaly> savedAnomalies = anomalyRepository.saveAll(anomalies);
        log.info("Bulk assignment completed successfully");
        
        return savedAnomalies.stream()
                .map(anomalyMapper::toDto)
                .collect(Collectors.toList());
    }

    // Helper Methods
    private void setAuditFields(Anomaly anomaly, boolean isNew) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUser = authentication != null ? authentication.getName() : "system";
        
        if (isNew) {
            anomaly.setCreatedBy(currentUser);
            anomaly.setCreatedAt(LocalDateTime.now());
            anomaly.setDetectedAt(LocalDateTime.now());
        } else {
            anomaly.setUpdatedBy(currentUser);
            anomaly.setUpdatedAt(LocalDateTime.now());
        }
    }

    private void updateAnomalyFields(Anomaly existingAnomaly, AnomalyDTO anomalyDto) {
        if (anomalyDto.getTitle() != null) existingAnomaly.setTitle(anomalyDto.getTitle());
        if (anomalyDto.getDescription() != null) existingAnomaly.setDescription(anomalyDto.getDescription());
        if (anomalyDto.getAnomalyType() != null) existingAnomaly.setAnomalyType(anomalyDto.getAnomalyType());
        if (anomalyDto.getSeverity() != null) existingAnomaly.setSeverity(anomalyDto.getSeverity());
        if (anomalyDto.getStatus() != null) existingAnomaly.setStatus(anomalyDto.getStatus());
        if (anomalyDto.getSourceIp() != null) existingAnomaly.setSourceIp(anomalyDto.getSourceIp());
        if (anomalyDto.getDestinationIp() != null) existingAnomaly.setDestinationIp(anomalyDto.getDestinationIp());
        if (anomalyDto.getSourcePort() != null) existingAnomaly.setSourcePort(anomalyDto.getSourcePort());
        if (anomalyDto.getDestinationPort() != null) existingAnomaly.setDestinationPort(anomalyDto.getDestinationPort());
        if (anomalyDto.getProtocol() != null) existingAnomaly.setProtocol(anomalyDto.getProtocol());
        if (anomalyDto.getAssetType() != null) existingAnomaly.setAssetType(anomalyDto.getAssetType());
        if (anomalyDto.getAssetCategory() != null) existingAnomaly.setAssetCategory(anomalyDto.getAssetCategory());
        if (anomalyDto.getPurdueLevel() != null) existingAnomaly.setPurdueLevel(anomalyDto.getPurdueLevel());
        if (anomalyDto.getManufacturer() != null) existingAnomaly.setManufacturer(anomalyDto.getManufacturer());
        if (anomalyDto.getModel() != null) existingAnomaly.setModel(anomalyDto.getModel());
        if (anomalyDto.getHostname() != null) existingAnomaly.setHostname(anomalyDto.getHostname());
        if (anomalyDto.getLocation() != null) existingAnomaly.setLocation(anomalyDto.getLocation());
        if (anomalyDto.getDepartment() != null) existingAnomaly.setDepartment(anomalyDto.getDepartment());
        if (anomalyDto.getEvidence() != null) existingAnomaly.setEvidence(anomalyDto.getEvidence());
        if (anomalyDto.getMitigationSteps() != null) existingAnomaly.setMitigationSteps(anomalyDto.getMitigationSteps());
        if (anomalyDto.getRecommendations() != null) existingAnomaly.setRecommendations(anomalyDto.getRecommendations());
        if (anomalyDto.getConfidenceScore() != null) existingAnomaly.setConfidenceScore(anomalyDto.getConfidenceScore());
        if (anomalyDto.getRiskScore() != null) existingAnomaly.setRiskScore(anomalyDto.getRiskScore());
        if (anomalyDto.getFalsePositiveProbability() != null) existingAnomaly.setFalsePositiveProbability(anomalyDto.getFalsePositiveProbability());
        if (anomalyDto.getMitreTactic() != null) existingAnomaly.setMitreTactic(anomalyDto.getMitreTactic());
        if (anomalyDto.getMitreTechnique() != null) existingAnomaly.setMitreTechnique(anomalyDto.getMitreTechnique());
        if (anomalyDto.getMitreId() != null) existingAnomaly.setMitreId(anomalyDto.getMitreId());
        if (anomalyDto.getTags() != null) existingAnomaly.setTags(anomalyDto.getTags());
        if (anomalyDto.getIndicators() != null) existingAnomaly.setIndicators(anomalyDto.getIndicators());
        if (anomalyDto.getCustomFields() != null) existingAnomaly.setCustomFields(anomalyDto.getCustomFields());
        if (anomalyDto.getAssignedTo() != null) existingAnomaly.setAssignedTo(anomalyDto.getAssignedTo());
        if (anomalyDto.getNotes() != null) existingAnomaly.setNotes(anomalyDto.getNotes());
        if (anomalyDto.getIsActive() != null) existingAnomaly.setIsActive(anomalyDto.getIsActive());
        if (anomalyDto.getIsEscalated() != null) existingAnomaly.setIsEscalated(anomalyDto.getIsEscalated());
        if (anomalyDto.getIsAcknowledged() != null) existingAnomaly.setIsAcknowledged(anomalyDto.getIsAcknowledged());
        if (anomalyDto.getIsResolved() != null) existingAnomaly.setIsResolved(anomalyDto.getIsResolved());
        if (anomalyDto.getIsFalsePositive() != null) existingAnomaly.setIsFalsePositive(anomalyDto.getIsFalsePositive());
    }
} 