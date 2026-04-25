package com.safetech.otshield.controller;

import com.safetech.otshield.dto.fakehmi.*;
import com.safetech.otshield.service.fakehmi.FakeHmiService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST endpoints for the Fake HMI deception sub-feature.
 * See FakeHmiService for the simulation engine.
 */
@RestController
@RequestMapping("/api/deception/hmis")
@CrossOrigin(origins = {"http://localhost:3000", "http://127.0.0.1:3000"})
public class FakeHmiController {

    private final FakeHmiService service;

    public FakeHmiController(FakeHmiService service) {
        this.service = service;
    }

    @GetMapping
    public ResponseEntity<List<FakeHmiInstanceDTO>> list() {
        return ResponseEntity.ok(service.listInstances());
    }

    @GetMapping("/{id}")
    public ResponseEntity<FakeHmiInstanceDTO> get(@PathVariable String id) {
        FakeHmiInstanceDTO h = service.getInstance(id);
        return h == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(h);
    }

    @GetMapping("/stats")
    public ResponseEntity<FakeHmiStatsDTO> stats() {
        return ResponseEntity.ok(service.stats());
    }

    @PostMapping("/{id}/interact")
    public ResponseEntity<HmiInteractionDTO> interact(@PathVariable String id,
                                                      @RequestBody HmiInteractionRequest req,
                                                      HttpServletRequest http) {
        String remote = http.getRemoteAddr();
        HmiInteractionDTO ix = service.recordInteraction(id, req, remote);
        return ix == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(ix);
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
                "status", "healthy",
                "service", "fake-hmi",
                "instances", service.listInstances().size()
        ));
    }
}
