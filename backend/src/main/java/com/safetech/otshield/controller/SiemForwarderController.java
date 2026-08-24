package com.safetech.otshield.controller;

import com.safetech.otshield.service.integration.SiemForwarderService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Configure and monitor SIEM event forwarding (RFC 5424 syslog / CEF).
 * OTShield pushes its deception + anomaly events into the customer's existing
 * SIEM instead of trying to replace it.
 */
@RestController
@RequestMapping("/api/integrations/siem")
@CrossOrigin(origins = {"http://localhost:3000", "http://127.0.0.1:3000"})
public class SiemForwarderController {

    private final SiemForwarderService service;

    public SiemForwarderController(SiemForwarderService service) {
        this.service = service;
    }

    @GetMapping("/config")
    public ResponseEntity<Map<String, Object>> getConfig() {
        return ResponseEntity.ok(service.getConfig());
    }

    @PutMapping("/config")
    public ResponseEntity<Map<String, Object>> updateConfig(@RequestBody Map<String, Object> req) {
        return ResponseEntity.ok(service.updateConfig(req));
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> stats() {
        return ResponseEntity.ok(service.stats());
    }

    @PostMapping("/test")
    public ResponseEntity<Map<String, Object>> test() {
        return ResponseEntity.ok(service.sendTest());
    }
}
