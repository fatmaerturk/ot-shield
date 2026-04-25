package com.safetech.otshield.controller;

import com.safetech.otshield.dto.AlertRuleDTO;
import com.safetech.otshield.mapper.AlertRuleMapper;
import com.safetech.otshield.mapper.AlertRule;
import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.AlertType;
import com.safetech.otshield.repository.AlertRuleRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * REST Controller for managing alert rules
 * Provides CRUD operations and rule management capabilities for alert generation
 */
@RestController
@RequestMapping("/api/alert-rules")
@RequiredArgsConstructor
public class AlertRuleController {

    private final AlertRuleRepository alertRuleRepository;
    private final AlertRuleMapper alertRuleMapper;

    /**
     * Get all alert rules with pagination and sorting
     */
    @GetMapping
    public ResponseEntity<Page<AlertRuleDTO>> getAllAlertRules(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "DESC") String sortDir) {
        
        Sort sort = sortDir.equalsIgnoreCase("ASC") ? 
            Sort.by(sortBy).ascending() : Sort.by(sortBy).descending();
        Pageable pageable = PageRequest.of(page, size, sort);
        
        Page<AlertRule> rules = alertRuleRepository.findAll(pageable);
        Page<AlertRuleDTO> ruleDtos = rules.map(alertRuleMapper::toDto);
        return ResponseEntity.ok(ruleDtos);
    }

    /**
     * Get alert rule by ID
     */
    @GetMapping("/{id}")
    public ResponseEntity<AlertRuleDTO> getAlertRuleById(@PathVariable String id) {
        Optional<AlertRule> rule = alertRuleRepository.findById(id);
        return rule.map(alertRuleMapper::toDto)
                  .map(ResponseEntity::ok)
                  .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Get alert rule by name
     */
    @GetMapping("/name/{name}")
    public ResponseEntity<AlertRuleDTO> getAlertRuleByName(@PathVariable String name) {
        Optional<AlertRule> rule = alertRuleRepository.findByName(name);
        return rule.map(alertRuleMapper::toDto)
                  .map(ResponseEntity::ok)
                  .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Create a new alert rule
     */
    @PostMapping
    public ResponseEntity<AlertRuleDTO> createAlertRule(@RequestBody AlertRuleDTO ruleDto) {
        // Check if rule with same name already exists
        if (alertRuleRepository.findByName(ruleDto.getName()).isPresent()) {
            return ResponseEntity.badRequest().build();
        }
        
        AlertRule rule = alertRuleMapper.toEntity(ruleDto);
        AlertRule savedRule = alertRuleRepository.save(rule);
        AlertRuleDTO savedRuleDto = alertRuleMapper.toDto(savedRule);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedRuleDto);
    }

    /**
     * Update an existing alert rule
     */
    @PutMapping("/{id}")
    public ResponseEntity<AlertRuleDTO> updateAlertRule(@PathVariable String id, @RequestBody AlertRuleDTO ruleDto) {
        if (!alertRuleRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        
        AlertRule rule = alertRuleMapper.toEntity(ruleDto);
        rule.setId(id);
        AlertRule updatedRule = alertRuleRepository.save(rule);
        AlertRuleDTO updatedRuleDto = alertRuleMapper.toDto(updatedRule);
        return ResponseEntity.ok(updatedRuleDto);
    }

    /**
     * Delete an alert rule
     */
    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteAlertRule(@PathVariable String id) {
        if (!alertRuleRepository.existsById(id)) {
            return ResponseEntity.notFound().build();
        }
        
        alertRuleRepository.deleteById(id);
        return ResponseEntity.noContent().build();
    }

    /**
     * Get enabled alert rules
     */
    @GetMapping("/enabled")
    public ResponseEntity<List<AlertRuleDTO>> getEnabledRules() {
        List<AlertRule> rules = alertRuleRepository.findByEnabledTrue();
        List<AlertRuleDTO> ruleDtos = rules.stream()
                .map(alertRuleMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(ruleDtos);
    }

    /**
     * Get disabled alert rules
     */
    @GetMapping("/disabled")
    public ResponseEntity<List<AlertRuleDTO>> getDisabledRules() {
        List<AlertRule> rules = alertRuleRepository.findByEnabledFalse();
        List<AlertRuleDTO> ruleDtos = rules.stream()
                .map(alertRuleMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(ruleDtos);
    }

    /**
     * Get alert rules by severity
     */
    @GetMapping("/severity/{severity}")
    public ResponseEntity<List<AlertRuleDTO>> getAlertRulesBySeverity(@PathVariable AlertSeverity severity) {
        List<AlertRule> rules = alertRuleRepository.findBySeverity(severity);
        List<AlertRuleDTO> ruleDtos = rules.stream()
                .map(alertRuleMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(ruleDtos);
    }

    /**
     * Get alert rules by type
     */
    @GetMapping("/type/{type}")
    public ResponseEntity<List<AlertRuleDTO>> getAlertRulesByType(@PathVariable AlertType type) {
        List<AlertRule> rules = alertRuleRepository.findByType(type);
        List<AlertRuleDTO> ruleDtos = rules.stream()
                .map(alertRuleMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(ruleDtos);
    }

    /**
     * Get alert rules by category
     */
    @GetMapping("/category/{category}")
    public ResponseEntity<List<AlertRuleDTO>> getAlertRulesByCategory(@PathVariable String category) {
        List<AlertRule> rules = alertRuleRepository.findByCategory(category);
        List<AlertRuleDTO> ruleDtos = rules.stream()
                .map(alertRuleMapper::toDto)
                .collect(Collectors.toList());
        return ResponseEntity.ok(ruleDtos);
    }

    /**
     * Search alert rules by text in name, description, or category
     */
    @GetMapping("/search")
    public ResponseEntity<Page<AlertRuleDTO>> searchAlertRules(
            @RequestParam String searchTerm,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {
        
        Pageable pageable = PageRequest.of(page, size, Sort.by("createdAt").descending());
        Page<AlertRule> rules = alertRuleRepository.searchRules(searchTerm, pageable);
        Page<AlertRuleDTO> ruleDtos = rules.map(alertRuleMapper::toDto);
        return ResponseEntity.ok(ruleDtos);
    }

    /**
     * Enable an alert rule
     */
    @PostMapping("/{id}/enable")
    public ResponseEntity<AlertRuleDTO> enableAlertRule(@PathVariable String id) {
        Optional<AlertRule> ruleOpt = alertRuleRepository.findById(id);
        if (ruleOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        AlertRule rule = ruleOpt.get();
        rule.setEnabled(true);
        AlertRule updatedRule = alertRuleRepository.save(rule);
        AlertRuleDTO updatedRuleDto = alertRuleMapper.toDto(updatedRule);
        return ResponseEntity.ok(updatedRuleDto);
    }

    /**
     * Disable an alert rule
     */
    @PostMapping("/{id}/disable")
    public ResponseEntity<AlertRuleDTO> disableAlertRule(@PathVariable String id) {
        Optional<AlertRule> ruleOpt = alertRuleRepository.findById(id);
        if (ruleOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }
        
        AlertRule rule = ruleOpt.get();
        rule.setEnabled(false);
        AlertRule updatedRule = alertRuleRepository.save(rule);
        AlertRuleDTO updatedRuleDto = alertRuleMapper.toDto(updatedRule);
        return ResponseEntity.ok(updatedRuleDto);
    }

    /**
     * Get alert rule statistics
     */
    @GetMapping("/statistics")
    public ResponseEntity<Map<String, Object>> getAlertRuleStatistics() {
        Map<String, Object> stats = Map.of(
            "totalRules", alertRuleRepository.count(),
            "enabledRules", alertRuleRepository.countByEnabled(true),
            "disabledRules", alertRuleRepository.countByEnabled(false),
            "criticalRules", alertRuleRepository.countBySeverity(AlertSeverity.CRITICAL),
            "highRules", alertRuleRepository.countBySeverity(AlertSeverity.HIGH)
        );
        
        return ResponseEntity.ok(stats);
    }
} 