package com.safetech.otshield.controller;

import com.safetech.otshield.dto.decoy.*;
import com.safetech.otshield.service.decoy.DecoyService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/decoy")
@CrossOrigin(origins = {"http://localhost:3000", "http://127.0.0.1:3000"})
public class DecoyController {

    private final DecoyService service;

    public DecoyController(DecoyService service) {
        this.service = service;
    }

    @GetMapping("/instances")
    public ResponseEntity<List<DecoyInstanceDTO>> listInstances() {
        return ResponseEntity.ok(service.listInstances());
    }

    @GetMapping("/instances/{id}")
    public ResponseEntity<DecoyInstanceDTO> getInstance(@PathVariable String id) {
        DecoyInstanceDTO d = service.getInstance(id);
        return d == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(d);
    }

    @GetMapping("/engagements")
    public ResponseEntity<List<EngagementDTO>> listEngagements(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String decoyId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return ResponseEntity.ok(service.listEngagements(status, decoyId, page, size));
    }

    @GetMapping("/engagements/{id}")
    public ResponseEntity<EngagementDTO> getEngagement(@PathVariable String id) {
        EngagementDTO e = service.getEngagement(id);
        return e == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(e);
    }

    @GetMapping("/attackers/{ip}")
    public ResponseEntity<AttackerProfileDTO> getAttacker(@PathVariable String ip) {
        AttackerProfileDTO a = service.getAttacker(ip);
        return a == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(a);
    }

    @GetMapping("/stats")
    public ResponseEntity<DecoyStatsDTO> stats() {
        return ResponseEntity.ok(service.computeStats());
    }

    @PostMapping("/actions")
    public ResponseEntity<DecoyActionResultDTO> applyAction(@RequestBody DecoyActionRequest req) {
        String actor = currentUsername();
        DecoyActionResultDTO result = service.applyAction(req, actor);
        return ResponseEntity.ok(result);
    }

    @GetMapping("/actions/recent")
    public ResponseEntity<List<DecoyActionResultDTO>> recentActions(
            @RequestParam(defaultValue = "20") int limit) {
        return ResponseEntity.ok(service.recentActions(limit));
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of(
                "status", "healthy",
                "service", "decoy-layer",
                "instances", service.listInstances().size()
        ));
    }

    private String currentUsername() {
        try {
            Authentication a = SecurityContextHolder.getContext().getAuthentication();
            return a != null ? a.getName() : "anonymous";
        } catch (Exception e) {
            return "anonymous";
        }
    }
}
