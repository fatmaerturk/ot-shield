package com.safetech.otshield.controller;

import com.safetech.otshield.service.EngageMappingService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * MITRE Engage coverage: which defensive deception techniques OTShield is
 * actually exercising, mapped from live decoy + honeytoken + response state.
 * The defender-side complement to the ATT&CK for ICS view.
 */
@RestController
@RequestMapping("/api/engage")
@CrossOrigin(origins = {"http://localhost:3000", "http://127.0.0.1:3000"})
public class EngageController {

    private final EngageMappingService service;

    public EngageController(EngageMappingService service) {
        this.service = service;
    }

    @GetMapping("/matrix")
    public ResponseEntity<Map<String, Object>> matrix() {
        return ResponseEntity.ok(service.buildMatrix());
    }
}
