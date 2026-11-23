package com.safetech.otshield.controller;

import com.safetech.otshield.service.IngestionMonitorService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Live-ingestion monitoring: which sensors are feeding the platform and how
 * much. All data traces to real {@code /api/upload/pcap} uploads - see
 * {@link IngestionMonitorService}. Read-only; falls under the authenticated
 * default in SecurityConfig (operator-only view).
 */
@RestController
@RequestMapping("/api/ingestion")
@CrossOrigin(origins = {"http://localhost:3000", "http://127.0.0.1:3000"})
public class IngestionController {

    private final IngestionMonitorService service;

    public IngestionController(IngestionMonitorService service) {
        this.service = service;
    }

    @GetMapping("/summary")
    public ResponseEntity<Map<String, Object>> summary() {
        return ResponseEntity.ok(service.summary());
    }

    @GetMapping("/recent")
    public ResponseEntity<List<Map<String, Object>>> recent(
            @RequestParam(defaultValue = "50") int limit) {
        return ResponseEntity.ok(service.recent(limit));
    }
}
