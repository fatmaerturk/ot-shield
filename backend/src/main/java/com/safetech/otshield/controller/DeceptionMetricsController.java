package com.safetech.otshield.controller;

import com.safetech.otshield.service.DeceptionMetricsService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Deception effectiveness metrics - computed entirely from live first-party
 * state (telemetry, decoy fleet, honeytokens, cases).
 */
@RestController
@RequestMapping("/api/deception/metrics")
@CrossOrigin(origins = {"http://localhost:3000", "http://127.0.0.1:3000"})
public class DeceptionMetricsController {

    private final DeceptionMetricsService service;

    public DeceptionMetricsController(DeceptionMetricsService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> metrics() {
        return ResponseEntity.ok(service.metrics());
    }
}
