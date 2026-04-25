package com.safetech.otshield.controller;

import com.safetech.otshield.dto.AssetDTO;
import com.safetech.otshield.service.AssetService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("/api/assets")
@RequiredArgsConstructor
@Slf4j
public class AssetController {
    private final AssetService assetService;

    // CRUD Operations
    @PostMapping
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<AssetDTO> createAsset(@RequestBody AssetDTO assetDto) {
        log.info("Creating new asset: {}", assetDto.getName());
        AssetDTO createdAsset = assetService.createAsset(assetDto);
        return ResponseEntity.status(HttpStatus.CREATED).body(createdAsset);
    }

    @GetMapping("/{id}")
    public ResponseEntity<AssetDTO> getAssetById(@PathVariable String id) {
        log.debug("Fetching asset by ID: {}", id);
        Optional<AssetDTO> asset = assetService.getAssetById(id);
        return asset.map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping
    public ResponseEntity<Page<AssetDTO>> getAllAssets(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size,
            @RequestParam(defaultValue = "name") String sortBy,
            @RequestParam(defaultValue = "asc") String sortDir) {
        log.debug("Fetching all assets with pagination");
        Page<AssetDTO> assets = assetService.getAssetsWithPagination(page, size, sortBy, sortDir);
        return ResponseEntity.ok(assets);
    }

    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<AssetDTO> updateAsset(@PathVariable String id, @RequestBody AssetDTO assetDto) {
        log.info("Updating asset with ID: {}", id);
        
        Optional<AssetDTO> updatedAssetOpt = assetService.updateAsset(id, assetDto);
        
        if (updatedAssetOpt.isPresent()) {
            AssetDTO updatedAsset = updatedAssetOpt.get();
            return ResponseEntity.ok(updatedAsset);
        } else {
            log.warn("Asset not found with ID: {}", id);
            return ResponseEntity.notFound().build();
        }
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteAsset(@PathVariable String id) {
        log.info("Deleting asset with ID: {}", id);
        try {
            assetService.deleteAsset(id);
            return ResponseEntity.noContent().build();
        } catch (Exception e) {
            log.error("Error deleting asset: {}", e.getMessage());
            return ResponseEntity.notFound().build();
        }
    }

    // Search and Filter Operations
    @GetMapping("/search")
    public ResponseEntity<Page<AssetDTO>> searchAssets(
            @RequestParam(required = false) String name,
            @RequestParam(required = false) String ipAddress,
            @RequestParam(required = false) String assetType,
            @RequestParam(required = false) String purdueLevel,
            @RequestParam(required = false) String criticalityLevel,
            @RequestParam(required = false) Boolean isActive,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {
        log.debug("Searching assets with filters");
        Page<AssetDTO> assets = assetService.searchAssets(
                name, ipAddress, assetType, purdueLevel, criticalityLevel, isActive, page, size);
        return ResponseEntity.ok(assets);
    }

    @GetMapping("/type/{assetType}")
    public ResponseEntity<List<AssetDTO>> getAssetsByType(@PathVariable String assetType) {
        log.debug("Fetching assets by type: {}", assetType);
        List<AssetDTO> assets = assetService.getAssetsByType(assetType);
        return ResponseEntity.ok(assets);
    }

    @GetMapping("/purdue-level/{purdueLevel}")
    public ResponseEntity<List<AssetDTO>> getAssetsByPurdueLevel(@PathVariable String purdueLevel) {
        log.debug("Fetching assets by Purdue level: {}", purdueLevel);
        List<AssetDTO> assets = assetService.getAssetsByPurdueLevel(purdueLevel);
        return ResponseEntity.ok(assets);
    }

    @GetMapping("/criticality/{criticalityLevel}")
    public ResponseEntity<List<AssetDTO>> getAssetsByCriticalityLevel(@PathVariable String criticalityLevel) {
        log.debug("Fetching assets by criticality level: {}", criticalityLevel);
        List<AssetDTO> assets = assetService.getAssetsByCriticalityLevel(criticalityLevel);
        return ResponseEntity.ok(assets);
    }

    @GetMapping("/manufacturer/{manufacturer}")
    public ResponseEntity<List<AssetDTO>> getAssetsByManufacturer(@PathVariable String manufacturer) {
        log.debug("Fetching assets by manufacturer: {}", manufacturer);
        List<AssetDTO> assets = assetService.getAssetsByManufacturer(manufacturer);
        return ResponseEntity.ok(assets);
    }

    @GetMapping("/location/{location}")
    public ResponseEntity<List<AssetDTO>> getAssetsByLocation(@PathVariable String location) {
        log.debug("Fetching assets by location: {}", location);
        List<AssetDTO> assets = assetService.getAssetsByLocation(location);
        return ResponseEntity.ok(assets);
    }

    @GetMapping("/department/{department}")
    public ResponseEntity<List<AssetDTO>> getAssetsByDepartment(@PathVariable String department) {
        log.debug("Fetching assets by department: {}", department);
        List<AssetDTO> assets = assetService.getAssetsByDepartment(department);
        return ResponseEntity.ok(assets);
    }

    @GetMapping("/online")
    public ResponseEntity<List<AssetDTO>> getOnlineAssets() {
        log.debug("Fetching online assets");
        List<AssetDTO> assets = assetService.getOnlineAssets();
        return ResponseEntity.ok(assets);
    }

    @GetMapping("/offline")
    public ResponseEntity<List<AssetDTO>> getOfflineAssets() {
        log.debug("Fetching offline assets");
        List<AssetDTO> assets = assetService.getOfflineAssets();
        return ResponseEntity.ok(assets);
    }

    @GetMapping("/with-vulnerabilities")
    public ResponseEntity<List<AssetDTO>> getAssetsWithVulnerabilities() {
        log.debug("Fetching assets with vulnerabilities");
        List<AssetDTO> assets = assetService.getAssetsWithVulnerabilities();
        return ResponseEntity.ok(assets);
    }

    @GetMapping("/high-risk")
    public ResponseEntity<List<AssetDTO>> getHighRiskAssets() {
        log.debug("Fetching high risk assets");
        List<AssetDTO> assets = assetService.getHighRiskAssets();
        return ResponseEntity.ok(assets);
    }

    // Statistics and Analytics
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Long>> getAssetStatistics() {
        log.debug("Fetching asset statistics");
        Map<String, Long> stats = assetService.getAssetStatistics();
        return ResponseEntity.ok(stats);
    }

    @GetMapping("/stats/counts")
    public ResponseEntity<Map<String, Long>> getAssetCounts() {
        log.debug("Fetching asset counts");
        Map<String, Long> counts = assetService.getAssetCounts();
        return ResponseEntity.ok(counts);
    }

    @GetMapping("/stats/by-type")
    public ResponseEntity<Map<String, Long>> getAssetCountsByType() {
        log.debug("Fetching asset counts by type");
        Map<String, Long> counts = assetService.getAssetCountsByType();
        return ResponseEntity.ok(counts);
    }

    @GetMapping("/stats/by-purdue-level")
    public ResponseEntity<Map<String, Long>> getAssetCountsByPurdueLevel() {
        log.debug("Fetching asset counts by Purdue level");
        Map<String, Long> counts = assetService.getAssetCountsByPurdueLevel();
        return ResponseEntity.ok(counts);
    }

    @GetMapping("/stats/by-criticality")
    public ResponseEntity<Map<String, Long>> getAssetCountsByCriticality() {
        log.debug("Fetching asset counts by criticality");
        Map<String, Long> counts = assetService.getAssetCountsByCriticalityLevel();
        return ResponseEntity.ok(counts);
    }

    @GetMapping("/stats/by-manufacturer")
    public ResponseEntity<Map<String, Long>> getAssetCountsByManufacturer() {
        log.debug("Fetching asset counts by manufacturer");
        Map<String, Long> counts = assetService.getAssetCountsByManufacturer();
        return ResponseEntity.ok(counts);
    }

    @GetMapping("/stats/by-location")
    public ResponseEntity<Map<String, Long>> getAssetCountsByLocation() {
        log.debug("Fetching asset counts by location");
        Map<String, Long> counts = assetService.getAssetCountsByLocation();
        return ResponseEntity.ok(counts);
    }

    @GetMapping("/stats/by-department")
    public ResponseEntity<Map<String, Long>> getAssetCountsByDepartment() {
        log.debug("Fetching asset counts by department");
        Map<String, Long> counts = assetService.getAssetCountsByDepartment();
        return ResponseEntity.ok(counts);
    }

    // Bulk Operations
    @PostMapping("/bulk/update-status")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<List<AssetDTO>> bulkUpdateStatus(
            @RequestParam List<String> assetIds,
            @RequestParam Boolean isActive) {
        log.info("Bulk updating status for {} assets", assetIds.size());
        List<AssetDTO> updatedAssets = assetService.bulkUpdateStatus(assetIds, isActive);
        return ResponseEntity.ok(updatedAssets);
    }

    @PostMapping("/bulk/update-criticality")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<List<AssetDTO>> bulkUpdateCriticality(
            @RequestParam List<String> assetIds,
            @RequestParam String criticalityLevel) {
        log.info("Bulk updating criticality for {} assets", assetIds.size());
        List<AssetDTO> updatedAssets = assetService.bulkUpdateCriticality(assetIds, criticalityLevel);
        return ResponseEntity.ok(updatedAssets);
    }

    @PostMapping("/bulk/assign-owner")
    @PreAuthorize("hasRole('ADMIN') or hasRole('ANALYST')")
    public ResponseEntity<List<AssetDTO>> bulkAssignOwner(
            @RequestParam List<String> assetIds,
            @RequestParam String owner) {
        log.info("Bulk assigning owner for {} assets", assetIds.size());
        List<AssetDTO> updatedAssets = assetService.bulkAssignOwner(assetIds, owner);
        return ResponseEntity.ok(updatedAssets);
    }

    // Health Check
    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> healthCheck() {
        log.debug("Asset service health check");
        Map<String, String> health = Map.of(
                "status", "UP",
                "service", "AssetService",
                "timestamp", java.time.LocalDateTime.now().toString()
        );
        return ResponseEntity.ok(health);
    }
} 