package com.safetech.otshield.service;

import com.safetech.otshield.dto.AssetDTO;
import com.safetech.otshield.mapper.AssetMapper;
import com.safetech.otshield.model.Asset;
import com.safetech.otshield.repository.AssetRepository;
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

/**
 * Service class for Asset management operations
 * Provides business logic for asset CRUD operations and asset-related queries
 */
@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AssetService {

    private final AssetRepository assetRepository;
    private final AssetMapper assetMapper;

    /**
     * Create a new asset
     */
    public AssetDTO createAsset(AssetDTO assetDto) {
        log.info("Creating new asset: {}", assetDto.getName());
        
        Asset asset = assetMapper.toEntity(assetDto);
        
        // Set audit fields
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            asset.setCreatedBy(authentication.getName());
            asset.setUpdatedBy(authentication.getName());
        }
        
        // Set default values if not provided
        if (asset.getIsActive() == null) {
            asset.setIsActive(true);
        }
        if (asset.getIsOnline() == null) {
            asset.setIsOnline(true);
        }
        if (asset.getFirstSeen() == null) {
            asset.setFirstSeen(LocalDateTime.now());
        }
        if (asset.getLastSeen() == null) {
            asset.setLastSeen(LocalDateTime.now());
        }
        
        Asset savedAsset = assetRepository.save(asset);
        log.info("Asset created successfully with ID: {}", savedAsset.getId());
        
        return assetMapper.toDto(savedAsset);
    }

    /**
     * Get asset by ID
     */
    @Transactional(readOnly = true)
    public Optional<AssetDTO> getAssetById(String id) {
        log.debug("Fetching asset by ID: {}", id);
        return assetRepository.findById(id)
                .map(assetMapper::toDto);
    }

    /**
     * Get asset by IP address
     */
    @Transactional(readOnly = true)
    public Optional<AssetDTO> getAssetByIpAddress(String ipAddress) {
        log.debug("Fetching asset by IP address: {}", ipAddress);
        return assetRepository.findByIpAddress(ipAddress)
                .map(assetMapper::toDto);
    }

    /**
     * Get asset by MAC address
     */
    @Transactional(readOnly = true)
    public Optional<AssetDTO> getAssetByMacAddress(String macAddress) {
        log.debug("Fetching asset by MAC address: {}", macAddress);
        return assetRepository.findByMacAddress(macAddress)
                .map(assetMapper::toDto);
    }

    /**
     * Get asset by hostname
     */
    @Transactional(readOnly = true)
    public Optional<AssetDTO> getAssetByHostname(String hostname) {
        log.debug("Fetching asset by hostname: {}", hostname);
        return assetRepository.findByHostname(hostname)
                .map(assetMapper::toDto);
    }

    /**
     * Get all assets with pagination
     */
    @Transactional(readOnly = true)
    public Page<AssetDTO> getAllAssets(int page, int size, String sortBy, String sortDir) {
        log.debug("Fetching all assets with pagination: page={}, size={}, sortBy={}, sortDir={}", 
                 page, size, sortBy, sortDir);
        
        Sort sort = sortDir.equalsIgnoreCase("ASC") ? 
            Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        Pageable pageable = PageRequest.of(page, size, sort);
        
        Page<Asset> assets = assetRepository.findAll(pageable);
        return assets.map(assetMapper::toDto);
    }

    /**
     * Get assets with filters
     */
    @Transactional(readOnly = true)
    public Page<AssetDTO> getAssetsWithFilters(
            String name, String ipAddress, Asset.AssetType assetType,
            Asset.PurdueLevel purdueLevel, Asset.CriticalityLevel criticalityLevel,
            Boolean isActive, int page, int size) {
        
        log.debug("Fetching assets with filters: name={}, ipAddress={}, assetType={}, purdueLevel={}, criticalityLevel={}, isActive={}", 
                 name, ipAddress, assetType, purdueLevel, criticalityLevel, isActive);
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("name").ascending());
        Page<Asset> assets = assetRepository.findAssetsWithFilters(
                name, ipAddress, assetType, purdueLevel, criticalityLevel, isActive, pageable);
        
        return assets.map(assetMapper::toDto);
    }

    /**
     * Update an existing asset
     */
    public Optional<AssetDTO> updateAsset(String id, AssetDTO assetDto) {
        log.info("Updating asset with ID: {}", id);
        
        return assetRepository.findById(id)
                .map(existingAsset -> {
                    // Update fields from DTO
                    Asset updatedAsset = assetMapper.toEntity(assetDto);
                    updatedAsset.setId(id);
                    updatedAsset.setCreatedAt(existingAsset.getCreatedAt());
                    updatedAsset.setCreatedBy(existingAsset.getCreatedBy());
                    updatedAsset.setUpdatedAt(LocalDateTime.now());
                    
                    // Set audit fields
                    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                    if (authentication != null) {
                        updatedAsset.setUpdatedBy(authentication.getName());
                    }
                    
                    Asset savedAsset = assetRepository.save(updatedAsset);
                    log.info("Asset updated successfully: {}", id);
                    return assetMapper.toDto(savedAsset);
                });
    }

    /**
     * Delete an asset
     */
    public boolean deleteAsset(String id) {
        log.info("Deleting asset with ID: {}", id);
        
        if (assetRepository.existsById(id)) {
            assetRepository.deleteById(id);
            log.info("Asset deleted successfully: {}", id);
            return true;
        } else {
            log.warn("Asset not found for deletion: {}", id);
            return false;
        }
    }

    /**
     * Update asset's last seen timestamp
     */
    public void updateAssetLastSeen(String id) {
        log.debug("Updating last seen timestamp for asset: {}", id);
        
        assetRepository.findById(id).ifPresent(asset -> {
            asset.setLastSeen(LocalDateTime.now());
            asset.setIsOnline(true);
            assetRepository.save(asset);
        });
    }

    /**
     * Mark asset as offline
     */
    public void markAssetOffline(String id) {
        log.debug("Marking asset as offline: {}", id);
        
        assetRepository.findById(id).ifPresent(asset -> {
            asset.setIsOnline(false);
            assetRepository.save(asset);
        });
    }

    /**
     * Get assets by type
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsByType(Asset.AssetType assetType) {
        log.debug("Fetching assets by type: {}", assetType);
        List<Asset> assets = assetRepository.findByAssetType(assetType);
        return assetMapper.toDtoList(assets);
    }

    /**
     * Get assets by Purdue level
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsByPurdueLevel(Asset.PurdueLevel purdueLevel) {
        log.debug("Fetching assets by Purdue level: {}", purdueLevel);
        List<Asset> assets = assetRepository.findByPurdueLevel(purdueLevel);
        return assetMapper.toDtoList(assets);
    }

    /**
     * Get assets by criticality level
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsByCriticalityLevel(Asset.CriticalityLevel criticalityLevel) {
        log.debug("Fetching assets by criticality level: {}", criticalityLevel);
        List<Asset> assets = assetRepository.findByCriticalityLevel(criticalityLevel);
        return assetMapper.toDtoList(assets);
    }

    /**
     * Get active assets
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getActiveAssets() {
        log.debug("Fetching active assets");
        List<Asset> assets = assetRepository.findByIsActiveTrue();
        return assetMapper.toDtoList(assets);
    }

    /**
     * Get online assets
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getOnlineAssets() {
        log.debug("Fetching online assets");
        List<Asset> assets = assetRepository.findByIsOnlineTrue();
        return assetMapper.toDtoList(assets);
    }

    /**
     * Get assets with vulnerabilities
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsWithVulnerabilities() {
        log.debug("Fetching assets with vulnerabilities");
        List<Asset> assets = assetRepository.findAssetsWithVulnerabilities();
        return assetMapper.toDtoList(assets);
    }

    /**
     * Get assets that need maintenance soon
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsNeedingMaintenance(int daysAhead) {
        log.debug("Fetching assets needing maintenance within {} days", daysAhead);
        LocalDateTime deadline = LocalDateTime.now().plusDays(daysAhead);
        List<Asset> assets = assetRepository.findAssetsNeedingMaintenance(deadline);
        return assetMapper.toDtoList(assets);
    }

    /**
     * Get assets with expired warranty
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsWithExpiredWarranty() {
        log.debug("Fetching assets with expired warranty");
        List<Asset> assets = assetRepository.findAssetsWithExpiredWarranty(LocalDateTime.now());
        return assetMapper.toDtoList(assets);
    }

    /**
     * Get assets not seen recently
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsNotSeenSince(int daysAgo) {
        log.debug("Fetching assets not seen since {} days ago", daysAgo);
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(daysAgo);
        List<Asset> assets = assetRepository.findAssetsNotSeenSince(cutoffDate);
        return assetMapper.toDtoList(assets);
    }

    /**
     * Get assets with high risk scores
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsWithHighRiskScore(int minRiskScore) {
        log.debug("Fetching assets with risk score >= {}", minRiskScore);
        List<Asset> assets = assetRepository.findAssetsWithHighRiskScore(minRiskScore);
        return assetMapper.toDtoList(assets);
    }

    /**
     * Search assets by name
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> searchAssetsByName(String name) {
        log.debug("Searching assets by name: {}", name);
        List<Asset> assets = assetRepository.findByNameContainingIgnoreCase(name);
        return assetMapper.toDtoList(assets);
    }

    /**
     * Search assets by IP address
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> searchAssetsByIpAddress(String ipAddress) {
        log.debug("Searching assets by IP address: {}", ipAddress);
        List<Asset> assets = assetRepository.findByIpAddressContaining(ipAddress);
        return assetMapper.toDtoList(assets);
    }

    /**
     * Get assets by tag
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsByTag(String tag) {
        log.debug("Fetching assets by tag: {}", tag);
        List<Asset> assets = assetRepository.findByTag(tag);
        return assetMapper.toDtoList(assets);
    }

    /**
     * Get assets by multiple tags
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsByTags(List<String> tags) {
        log.debug("Fetching assets by tags: {}", tags);
        List<Asset> assets = assetRepository.findByTags(tags);
        return assetMapper.toDtoList(assets);
    }

    /**
     * Get asset statistics
     */
    @Transactional(readOnly = true)
    public Map<String, Long> getAssetStatistics() {
        log.debug("Fetching asset statistics");
        
        Map<String, Long> statistics = new HashMap<>();
        statistics.put("total", assetRepository.count());
        statistics.put("active", (long) assetRepository.findByIsActiveTrue().size());
        statistics.put("online", (long) assetRepository.findByIsOnlineTrue().size());
        statistics.put("offline", (long) assetRepository.findByIsOnlineFalse().size());
        statistics.put("withVulnerabilities", (long) assetRepository.findAssetsWithVulnerabilities().size());
        statistics.put("highRisk", (long) assetRepository.findByRiskScoreGreaterThan(70).size());
        statistics.put("needingMaintenance", (long) assetRepository.findAssetsNeedingMaintenance(LocalDateTime.now().plusDays(30)).size());
        statistics.put("expiredWarranty", (long) assetRepository.findAssetsWithExpiredWarranty(LocalDateTime.now()).size());
        
        return statistics;
    }

    /**
     * Get asset counts by type
     */
    @Transactional(readOnly = true)
    public Map<String, Long> getAssetCountsByType() {
        log.debug("Fetching asset counts by type");
        List<Object[]> results = assetRepository.countByAssetType();
        
        return results.stream()
                .collect(Collectors.toMap(
                    result -> ((Asset.AssetType) result[0]).getDisplayName(),
                    result -> (Long) result[1]
                ));
    }

    /**
     * Get asset counts by Purdue level
     */
    @Transactional(readOnly = true)
    public Map<String, Long> getAssetCountsByPurdueLevel() {
        log.debug("Fetching asset counts by Purdue level");
        List<Object[]> results = assetRepository.countByPurdueLevel();
        
        return results.stream()
                .collect(Collectors.toMap(
                    result -> ((Asset.PurdueLevel) result[0]).getDisplayName(),
                    result -> (Long) result[1]
                ));
    }

    /**
     * Get asset counts by criticality level
     */
    @Transactional(readOnly = true)
    public Map<String, Long> getAssetCountsByCriticalityLevel() {
        log.debug("Fetching asset counts by criticality level");
        List<Object[]> results = assetRepository.countByCriticalityLevel();
        
        return results.stream()
                .collect(Collectors.toMap(
                    result -> ((Asset.CriticalityLevel) result[0]).getDisplayName(),
                    result -> (Long) result[1]
                ));
    }

    /**
     * Bulk update asset status
     */
    public void bulkUpdateAssetStatus(List<String> assetIds, boolean isActive) {
        log.info("Bulk updating asset status for {} assets to active={}", assetIds.size(), isActive);
        
        List<Asset> assets = assetRepository.findAllById(assetIds);
        assets.forEach(asset -> {
            asset.setIsActive(isActive);
            asset.setUpdatedAt(LocalDateTime.now());
            
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null) {
                asset.setUpdatedBy(authentication.getName());
            }
        });
        
        assetRepository.saveAll(assets);
        log.info("Bulk asset status update completed");
    }

    /**
     * Check if asset exists by IP address
     */
    @Transactional(readOnly = true)
    public boolean assetExistsByIpAddress(String ipAddress) {
        return assetRepository.findByIpAddress(ipAddress).isPresent();
    }

    /**
     * Check if asset exists by MAC address
     */
    @Transactional(readOnly = true)
    public boolean assetExistsByMacAddress(String macAddress) {
        return assetRepository.findByMacAddress(macAddress).isPresent();
    }

    /**
     * Check if asset exists by hostname
     */
    @Transactional(readOnly = true)
    public boolean assetExistsByHostname(String hostname) {
        return assetRepository.findByHostname(hostname).isPresent();
    }

    /**
     * Get assets with pagination
     */
    @Transactional(readOnly = true)
    public Page<AssetDTO> getAssetsWithPagination(int page, int size, String sortBy, String sortDir) {
        log.debug("Fetching assets with pagination: page={}, size={}, sortBy={}, sortDir={}", page, size, sortBy, sortDir);
        
        Sort sort = sortDir.equalsIgnoreCase(Sort.Direction.ASC.name()) ? 
                Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        
        Pageable pageable = PageRequest.of(page, size, sort);
        return assetRepository.findAll(pageable)
                .map(assetMapper::toDto);
    }

    /**
     * Search assets with filters
     */
    @Transactional(readOnly = true)
    public Page<AssetDTO> searchAssets(String name, String ipAddress, String assetType, 
                                      String purdueLevel, String criticalityLevel, 
                                      Boolean isActive, int page, int size) {
        log.debug("Searching assets with filters");
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("name").ascending());
        
        Asset.AssetType type = null;
        if (assetType != null) {
            try {
                type = Asset.AssetType.valueOf(assetType.toUpperCase());
            } catch (IllegalArgumentException e) {
                log.warn("Invalid asset type: {}", assetType);
            }
        }
        
        Asset.PurdueLevel level = null;
        if (purdueLevel != null) {
            try {
                level = Asset.PurdueLevel.valueOf(purdueLevel.toUpperCase());
            } catch (IllegalArgumentException e) {
                log.warn("Invalid Purdue level: {}", purdueLevel);
            }
        }
        
        Asset.CriticalityLevel criticality = null;
        if (criticalityLevel != null) {
            try {
                criticality = Asset.CriticalityLevel.valueOf(criticalityLevel.toUpperCase());
            } catch (IllegalArgumentException e) {
                log.warn("Invalid criticality level: {}", criticalityLevel);
            }
        }
        
        return assetRepository.findAssetsWithFilters(name, ipAddress, type, level, criticality, isActive, pageable)
                .map(assetMapper::toDto);
    }

    /**
     * Get assets by type (string)
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsByType(String assetType) {
        log.debug("Fetching assets by type: {}", assetType);
        try {
            Asset.AssetType type = Asset.AssetType.valueOf(assetType.toUpperCase());
            return assetRepository.findByAssetType(type)
                    .stream()
                    .map(assetMapper::toDto)
                    .collect(Collectors.toList());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid asset type: {}", assetType);
            return List.of();
        }
    }

    /**
     * Get assets by Purdue level (string)
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsByPurdueLevel(String purdueLevel) {
        log.debug("Fetching assets by Purdue level: {}", purdueLevel);
        try {
            Asset.PurdueLevel level = Asset.PurdueLevel.valueOf(purdueLevel.toUpperCase());
            return assetRepository.findByPurdueLevel(level)
                    .stream()
                    .map(assetMapper::toDto)
                    .collect(Collectors.toList());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid Purdue level: {}", purdueLevel);
            return List.of();
        }
    }

    /**
     * Get assets by criticality level (string)
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsByCriticalityLevel(String criticalityLevel) {
        log.debug("Fetching assets by criticality level: {}", criticalityLevel);
        try {
            Asset.CriticalityLevel criticality = Asset.CriticalityLevel.valueOf(criticalityLevel.toUpperCase());
            return assetRepository.findByCriticalityLevel(criticality)
                    .stream()
                    .map(assetMapper::toDto)
                    .collect(Collectors.toList());
        } catch (IllegalArgumentException e) {
            log.warn("Invalid criticality level: {}", criticalityLevel);
            return List.of();
        }
    }

    /**
     * Get assets by manufacturer
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsByManufacturer(String manufacturer) {
        log.debug("Fetching assets by manufacturer: {}", manufacturer);
        return assetRepository.findByManufacturer(manufacturer)
                .stream()
                .map(assetMapper::toDto)
                .collect(Collectors.toList());
    }

    /**
     * Get assets by location
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsByLocation(String location) {
        log.debug("Fetching assets by location: {}", location);
        return assetRepository.findByLocation(location)
                .stream()
                .map(assetMapper::toDto)
                .collect(Collectors.toList());
    }

    /**
     * Get assets by department
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getAssetsByDepartment(String department) {
        log.debug("Fetching assets by department: {}", department);
        return assetRepository.findByDepartment(department)
                .stream()
                .map(assetMapper::toDto)
                .collect(Collectors.toList());
    }

    /**
     * Get offline assets
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getOfflineAssets() {
        log.debug("Fetching offline assets");
        return assetRepository.findByIsOnlineFalse()
                .stream()
                .map(assetMapper::toDto)
                .collect(Collectors.toList());
    }

    /**
     * Get high risk assets
     */
    @Transactional(readOnly = true)
    public List<AssetDTO> getHighRiskAssets() {
        log.debug("Fetching high risk assets");
        return assetRepository.findByRiskScoreGreaterThan(70)
                .stream()
                .map(assetMapper::toDto)
                .collect(Collectors.toList());
    }

    /**
     * Get asset counts
     */
    @Transactional(readOnly = true)
    public Map<String, Long> getAssetCounts() {
        log.debug("Calculating asset counts");
        return getAssetStatistics();
    }

    /**
     * Get asset counts by manufacturer
     */
    @Transactional(readOnly = true)
    public Map<String, Long> getAssetCountsByManufacturer() {
        log.debug("Calculating asset counts by manufacturer");
        return assetRepository.findAll()
                .stream()
                .filter(asset -> asset.getManufacturer() != null)
                .collect(Collectors.groupingBy(
                        Asset::getManufacturer,
                        Collectors.counting()
                ));
    }

    /**
     * Get asset counts by location
     */
    @Transactional(readOnly = true)
    public Map<String, Long> getAssetCountsByLocation() {
        log.debug("Calculating asset counts by location");
        return assetRepository.findAll()
                .stream()
                .filter(asset -> asset.getLocation() != null)
                .collect(Collectors.groupingBy(
                        Asset::getLocation,
                        Collectors.counting()
                ));
    }

    /**
     * Get asset counts by department
     */
    @Transactional(readOnly = true)
    public Map<String, Long> getAssetCountsByDepartment() {
        log.debug("Calculating asset counts by department");
        return assetRepository.findAll()
                .stream()
                .filter(asset -> asset.getDepartment() != null)
                .collect(Collectors.groupingBy(
                        Asset::getDepartment,
                        Collectors.counting()
                ));
    }

    /**
     * Bulk update status
     */
    public List<AssetDTO> bulkUpdateStatus(List<String> assetIds, Boolean isActive) {
        log.info("Bulk updating status for {} assets to: {}", assetIds.size(), isActive);
        
        List<Asset> assets = assetRepository.findAllById(assetIds);
        assets.forEach(asset -> {
            asset.setIsActive(isActive);
            setAuditFields(asset, false);
        });
        
        List<Asset> savedAssets = assetRepository.saveAll(assets);
        log.info("Bulk status update completed successfully");
        
        return savedAssets.stream()
                .map(assetMapper::toDto)
                .collect(Collectors.toList());
    }

    /**
     * Bulk update criticality
     */
    public List<AssetDTO> bulkUpdateCriticality(List<String> assetIds, String criticalityLevel) {
        log.info("Bulk updating criticality for {} assets to: {}", assetIds.size(), criticalityLevel);
        
        try {
            Asset.CriticalityLevel criticality = Asset.CriticalityLevel.valueOf(criticalityLevel.toUpperCase());
            
            List<Asset> assets = assetRepository.findAllById(assetIds);
            assets.forEach(asset -> {
                asset.setCriticalityLevel(criticality);
                setAuditFields(asset, false);
            });
            
            List<Asset> savedAssets = assetRepository.saveAll(assets);
            log.info("Bulk criticality update completed successfully");
            
            return savedAssets.stream()
                    .map(assetMapper::toDto)
                    .collect(Collectors.toList());
        } catch (IllegalArgumentException e) {
            log.error("Invalid criticality level: {}", criticalityLevel);
            throw new RuntimeException("Invalid criticality level: " + criticalityLevel);
        }
    }

    /**
     * Bulk assign owner
     */
    public List<AssetDTO> bulkAssignOwner(List<String> assetIds, String owner) {
        log.info("Bulk assigning owner for {} assets to: {}", assetIds.size(), owner);
        
        List<Asset> assets = assetRepository.findAllById(assetIds);
        assets.forEach(asset -> {
            asset.setOwner(owner);
            setAuditFields(asset, false);
        });
        
        List<Asset> savedAssets = assetRepository.saveAll(assets);
        log.info("Bulk owner assignment completed successfully");
        
        return savedAssets.stream()
                .map(assetMapper::toDto)
                .collect(Collectors.toList());
    }

    /**
     * Helper method to set audit fields
     */
    private void setAuditFields(Asset asset, boolean isNew) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentUser = authentication != null ? authentication.getName() : "system";
        
        if (isNew) {
            asset.setCreatedBy(currentUser);
            asset.setCreatedAt(LocalDateTime.now());
        } else {
            asset.setUpdatedBy(currentUser);
            asset.setUpdatedAt(LocalDateTime.now());
        }
    }
} 