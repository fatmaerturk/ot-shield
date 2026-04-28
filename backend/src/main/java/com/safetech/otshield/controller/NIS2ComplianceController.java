package com.safetech.otshield.controller;

import com.safetech.otshield.service.NIS2ComplianceService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * NIS2 Directive (EU 2022/2555) compliance endpoints. Drives the
 * /compliance/nis2 frontend page.
 */
@RestController
@RequestMapping("/api/compliance/nis2")
public class NIS2ComplianceController {

    private final NIS2ComplianceService service;

    public NIS2ComplianceController(NIS2ComplianceService service) {
        this.service = service;
    }

    /** Full posture payload — drives the page. */
    @GetMapping("/posture")
    public ResponseEntity<Map<String, Object>> getPosture() {
        try {
            return ResponseEntity.ok(service.buildPosture());
        } catch (Exception e) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(err);
        }
    }

    /** Generate a NIS2 Article 23.4(a) early-warning report for one alert. */
    @GetMapping("/early-warning/{alertId}")
    public ResponseEntity<Map<String, Object>> earlyWarning(@PathVariable String alertId) {
        try {
            return ResponseEntity.ok(service.generateEarlyWarningReport(alertId));
        } catch (Exception e) {
            Map<String, Object> err = new HashMap<>();
            err.put("error", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(err);
        }
    }
}
