package com.safetech.otshield.controller;

import com.safetech.otshield.service.IEC62443ComplianceService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Live ISA/IEC 62443-3-3 (System Security Requirements) compliance posture,
 * derived from real OTShield telemetry. Mirrors {@code NIS2ComplianceController}.
 */
@RestController
@RequestMapping("/api/compliance/iec62443")
@RequiredArgsConstructor
@Slf4j
public class IEC62443ComplianceController {

    private final IEC62443ComplianceService service;

    @GetMapping("/posture")
    public ResponseEntity<Map<String, Object>> getPosture() {
        try {
            return ResponseEntity.ok(service.buildPosture());
        } catch (Exception e) {
            log.error("Failed to build IEC 62443 posture", e);
            return ResponseEntity.status(500).body(Map.of("error", e.getMessage() == null ? "error" : e.getMessage()));
        }
    }
}
