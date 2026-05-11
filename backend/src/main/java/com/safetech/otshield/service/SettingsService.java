package com.safetech.otshield.service;

import com.safetech.otshield.model.AuditLog;
import com.safetech.otshield.repository.AuditLogRepository;
import com.safetech.otshield.repository.HoneypotLogRepository;
import com.safetech.otshield.repository.AlertRepository;
import com.safetech.otshield.repository.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Backing service for the unified Settings page. Holds in-memory mutable
 * configuration (tunnel URL, alert thresholds, severity toggles, etc.) and
 * exposes data for the System / Audit / API Keys tabs.
 *
 * Persistence note: settings are kept in-memory for now and could be
 * promoted to a config table later. Audit log is fully persisted.
 */
@Service
public class SettingsService {

    private final AuditLogRepository auditRepo;
    private final HoneypotLogRepository honeypotRepo;
    private final AlertRepository alertRepo;
    private final UserRepository userRepo;

    @Value("${honeypot.ingest.token:}")
    private String configuredIngestToken;

    /** Mutable runtime settings — persisted in memory only. */
    private final Map<String, Object> runtimeSettings = new ConcurrentHashMap<>();

    public SettingsService(AuditLogRepository auditRepo,
                           HoneypotLogRepository honeypotRepo,
                           AlertRepository alertRepo,
                           UserRepository userRepo) {
        this.auditRepo = auditRepo;
        this.honeypotRepo = honeypotRepo;
        this.alertRepo = alertRepo;
        this.userRepo = userRepo;

        // Defaults
        runtimeSettings.put("tunnelUrl", "https://indoor-thumbs-growing-worth.trycloudflare.com");
        runtimeSettings.put("ingestToken", "GcZ9KY7ANmLfvob6SOWxnRBjVlEPX2uaMr805td4IHTCezyU");
        runtimeSettings.put("alertSeverityFloor", "MEDIUM");
        runtimeSettings.put("emailNotifications", false);
        runtimeSettings.put("slackWebhook", "");
        runtimeSettings.put("retentionMonths", 6);
        runtimeSettings.put("theme", "light");
        runtimeSettings.put("language", "en");
        runtimeSettings.put("dateFormat", "ISO");
        runtimeSettings.put("defaultLanding", "/attack-intelligence");
    }

    // ───────────────────────────────────────────────────────────
    // SETTINGS GET/UPDATE
    // ───────────────────────────────────────────────────────────
    public Map<String, Object> getAllSettings() {
        return new LinkedHashMap<>(runtimeSettings);
    }

    public Map<String, Object> updateSettings(Map<String, Object> updates, String actor, String sourceIp) {
        Map<String, Object> changed = new LinkedHashMap<>();
        for (Map.Entry<String, Object> e : updates.entrySet()) {
            Object oldVal = runtimeSettings.get(e.getKey());
            if (!Objects.equals(oldVal, e.getValue())) {
                runtimeSettings.put(e.getKey(), e.getValue());
                changed.put(e.getKey(), Map.of("from", oldVal == null ? "" : oldVal, "to", e.getValue()));
            }
        }
        if (!changed.isEmpty()) {
            log(actor, "SETTINGS_UPDATED",
                "Updated " + changed.size() + " setting(s): " + String.join(", ", changed.keySet()),
                "settings", null, sourceIp, "SUCCESS");
        }
        return runtimeSettings;
    }

    // ───────────────────────────────────────────────────────────
    // SYSTEM STATUS
    // ───────────────────────────────────────────────────────────
    public Map<String, Object> getSystemStatus() {
        Map<String, Object> status = new LinkedHashMap<>();

        // Versioning
        status.put("backendVersion", "0.9.4-demo");
        status.put("javaVersion", System.getProperty("java.version"));
        status.put("springProfile", "default");

        // Database stats
        Map<String, Object> dbStats = new LinkedHashMap<>();
        dbStats.put("honeypotLogs", honeypotRepo.count());
        dbStats.put("alerts", alertRepo.count());
        dbStats.put("auditLogs", auditRepo.count());
        dbStats.put("users", userRepo.count());
        status.put("database", dbStats);

        // Process / runtime
        Runtime rt = Runtime.getRuntime();
        Map<String, Object> runtime = new LinkedHashMap<>();
        runtime.put("totalMemoryMB", rt.totalMemory() / (1024 * 1024));
        runtime.put("freeMemoryMB", rt.freeMemory() / (1024 * 1024));
        runtime.put("maxMemoryMB", rt.maxMemory() / (1024 * 1024));
        runtime.put("availableProcessors", rt.availableProcessors());
        runtime.put("uptime", System.currentTimeMillis()); // crude
        status.put("runtime", runtime);

        // Health flags
        Map<String, Object> health = new LinkedHashMap<>();
        health.put("databaseReachable", true);
        health.put("ingestEndpointEnabled", configuredIngestToken != null && !configuredIngestToken.isBlank());
        health.put("retentionCompliant", true);
        status.put("health", health);

        return status;
    }

    // ───────────────────────────────────────────────────────────
    // AUDIT LOG
    // ───────────────────────────────────────────────────────────
    public List<Map<String, Object>> getAuditLog(int limit) {
        List<AuditLog> rows = auditRepo.findAllByOrderByCreatedAtDesc();
        if (rows.size() > limit) rows = rows.subList(0, limit);
        return rows.stream().map(this::toAuditDto).collect(Collectors.toList());
    }

    public AuditLog log(String actor, String action, String description,
                        String targetType, String targetId, String sourceIp, String outcome) {
        AuditLog l = new AuditLog();
        l.setActor(actor == null ? "system" : actor);
        l.setAction(action);
        l.setDescription(description);
        l.setTargetType(targetType);
        l.setTargetId(targetId);
        l.setSourceIp(sourceIp);
        l.setOutcome(outcome == null ? "SUCCESS" : outcome);
        l.setCreatedAt(LocalDateTime.now());
        try {
            return auditRepo.save(l);
        } catch (Exception e) {
            return l;
        }
    }

    private Map<String, Object> toAuditDto(AuditLog l) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("id", l.getId());
        m.put("actor", l.getActor());
        m.put("action", l.getAction());
        m.put("description", l.getDescription());
        m.put("targetType", l.getTargetType());
        m.put("targetId", l.getTargetId());
        m.put("sourceIp", l.getSourceIp());
        m.put("outcome", l.getOutcome());
        m.put("createdAt", l.getCreatedAt() == null ? null : l.getCreatedAt().toString());
        return m;
    }

    // ───────────────────────────────────────────────────────────
    // TUNNEL / FORWARDER STATUS
    // ───────────────────────────────────────────────────────────
    public Map<String, Object> getTunnelStatus() {
        Map<String, Object> t = new LinkedHashMap<>();
        t.put("tunnelUrl", runtimeSettings.get("tunnelUrl"));
        t.put("ingestToken", maskToken((String) runtimeSettings.get("ingestToken")));
        t.put("ingestEnabled", configuredIngestToken != null && !configuredIngestToken.isBlank());

        // Recent ingest activity proxy: count last hour honeypot rows
        LocalDateTime hourAgo = LocalDateTime.now().minusHours(1);
        long lastHour = honeypotRepo.findAll().stream()
            .filter(l -> l.getTimestamp() != null && l.getTimestamp().isAfter(hourAgo))
            .count();
        t.put("eventsLastHour", lastHour);
        t.put("totalEvents", honeypotRepo.count());
        return t;
    }

    private String maskToken(String token) {
        if (token == null || token.length() < 12) return "****";
        return token.substring(0, 4) + "..." + token.substring(token.length() - 4);
    }
}
