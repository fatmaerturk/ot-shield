package com.safetech.otshield.controller;

import com.safetech.otshield.service.SettingsService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/settings")
public class SettingsController {

    private final SettingsService settingsService;

    public SettingsController(SettingsService settingsService) {
        this.settingsService = settingsService;
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> getAll() {
        return ResponseEntity.ok(settingsService.getAllSettings());
    }

    @PutMapping
    public ResponseEntity<Map<String, Object>> update(@RequestBody Map<String, Object> updates,
                                                      HttpServletRequest req) {
        String actor = extractActor(req);
        String ip = req.getRemoteAddr();
        return ResponseEntity.ok(settingsService.updateSettings(updates, actor, ip));
    }

    @GetMapping("/system-status")
    public ResponseEntity<Map<String, Object>> systemStatus() {
        return ResponseEntity.ok(settingsService.getSystemStatus());
    }

    @GetMapping("/audit-log")
    public ResponseEntity<List<Map<String, Object>>> auditLog(
        @RequestParam(defaultValue = "200") int limit
    ) {
        return ResponseEntity.ok(settingsService.getAuditLog(limit));
    }

    @GetMapping("/tunnel-status")
    public ResponseEntity<Map<String, Object>> tunnelStatus() {
        return ResponseEntity.ok(settingsService.getTunnelStatus());
    }

    @PostMapping("/rotate-token")
    public ResponseEntity<Map<String, Object>> rotateToken(HttpServletRequest req) {
        String actor = extractActor(req);
        String ip = req.getRemoteAddr();
        // Generate a new opaque token (server-side only; user must update forwarder)
        String newToken = java.util.UUID.randomUUID().toString().replace("-", "")
            + java.util.UUID.randomUUID().toString().replace("-", "");
        Map<String, Object> updates = new HashMap<>();
        updates.put("ingestToken", newToken);
        settingsService.updateSettings(updates, actor, ip);
        settingsService.log(actor, "TOKEN_ROTATED", "Honeypot ingest token rotated",
            "settings", "ingestToken", ip, "SUCCESS");
        Map<String, Object> resp = new HashMap<>();
        resp.put("ok", true);
        resp.put("newToken", newToken);
        resp.put("warning",
            "Update the forwarder OTSHIELD_INGEST_TOKEN env var or new attacks will not be ingested.");
        return ResponseEntity.ok(resp);
    }

    private String extractActor(HttpServletRequest req) {
        java.security.Principal principal = req.getUserPrincipal();
        if (principal != null) return principal.getName();
        String header = req.getHeader("X-User");
        return header == null ? "anonymous" : header;
    }
}
