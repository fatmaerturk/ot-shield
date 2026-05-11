package com.safetech.otshield.controller;

import com.safetech.otshield.model.HoneypotLog;
import com.safetech.otshield.service.ConpotLogIntegrationService;
import com.safetech.otshield.service.HoneypotEventPublisher;
import com.safetech.otshield.service.HoneypotLogService;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@RequestMapping("/api/honeypot")
public class HoneypotController {

    private static final Logger log = LoggerFactory.getLogger(HoneypotController.class);

    private final HoneypotLogService honeypotLogService;
    private final ConpotLogIntegrationService conpotLogIntegrationService;
    private final HoneypotEventPublisher eventPublisher;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private com.safetech.otshield.service.ConpotService conpotService;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private com.safetech.otshield.service.TTPAnalysisService ttpAnalysisService;

    /** Optional — used to mirror real Docker tripwire hits onto the matching
     *  fake HMI card (ALARM + INTERACTION) so the deception UI shows live
     *  attacker activity alongside the simulated process drift. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private com.safetech.otshield.service.fakehmi.FakeHmiService fakeHmiService;

    /** Shared secret used by remote sidecars (e.g. the GCP VM Conpot forwarder)
     *  to authenticate to /api/honeypot/ingest. Configure in application.properties. */
    @Value("${honeypot.ingest.token:}")
    private String ingestToken;

    public HoneypotController(HoneypotLogService honeypotLogService,
                              ConpotLogIntegrationService conpotLogIntegrationService,
                              HoneypotEventPublisher eventPublisher) {
        this.honeypotLogService = honeypotLogService;
        this.conpotLogIntegrationService = conpotLogIntegrationService;
        this.eventPublisher = eventPublisher;
    }

    /**
     * Server-Sent Events stream of real honeypot hits. The Attack Intelligence
     * map subscribes here and spawns one animated arc per "attack" event so the
     * visualisation reflects actual telemetry instead of a random timer.
     * Internal-noise rows are filtered upstream in HoneypotLogService.
     */
    @GetMapping(value = "/events", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamEvents() {
        return eventPublisher.register();
    }

    @GetMapping("/logs")
    public ResponseEntity<List<HoneypotLog>> getLogs(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size,
            @RequestParam(required = false) String sourceIp,
            @RequestParam(required = false) String protocol) {
        
        List<HoneypotLog> logs = honeypotLogService.getLogs(page, size, sourceIp, protocol);
        return ResponseEntity.ok(logs);
    }

    @GetMapping("/logs/recent")
    public ResponseEntity<List<HoneypotLog>> getRecentLogs(
            @RequestParam(defaultValue = "10") int count) {
        
        List<HoneypotLog> logs = honeypotLogService.getRecentLogs(count);
        return ResponseEntity.ok(logs);
    }

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        Map<String, Object> stats = honeypotLogService.getStats();
        return ResponseEntity.ok(stats);
    }

    @GetMapping("/attacks")
    public ResponseEntity<List<Map<String, Object>>> getAttackAttempts() {
        List<Map<String, Object>> attacks = honeypotLogService.getAttackAttempts();
        return ResponseEntity.ok(attacks);
    }

    /**
     * Attacker TTPs &amp; Behavioral Intelligence — derived analytics over the
     * honeypot_logs table. Returns a single payload that drives the
     * "Attacker TTPs &amp; Behavioral Intel" tab on the Attack Intelligence page:
     *  - per-IP attacker profiles + sophistication scoring
     *  - MITRE ATT&amp;CK ICS tactic heatmap
     *  - tool / wordlist fingerprints
     *  - per-attacker kill-chain timelines
     *  - geographic distribution
     *  - credential intelligence (Mirai / ICS default detection)
     *  - behavioral anomalies (burst, slow-low, multi-protocol pivot)
     */
    @GetMapping("/ttp-analysis")
    public ResponseEntity<Map<String, Object>> getTTPAnalysis() {
        if (ttpAnalysisService == null) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(Map.of("error", "TTPAnalysisService not available"));
        }
        try {
            Map<String, Object> report = ttpAnalysisService.buildTTPReport();
            return ResponseEntity.ok(report);
        } catch (Exception e) {
            log.error("Failed to build TTP analysis report", e);
            Map<String, Object> err = new HashMap<>();
            err.put("error", "TTP analysis failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(err);
        }
    }

    @PostMapping("/logs/clear")
    public ResponseEntity<String> clearLogs() {
        honeypotLogService.clearLogs();
        return ResponseEntity.ok("Logs cleared successfully");
    }

    /**
     * One-shot backfill: walk every existing honeypot_logs row and create an
     * Alert for each one that qualifies (skips internal noise, skips LOW
     * external rows, and skips rows that already have a matching Alert).
     * Safe to call repeatedly — duplicate detection uses the honeypot:&lt;id&gt;
     * tag stored on each fanned-out alert.
     */
    @PostMapping("/alerts/backfill")
    public ResponseEntity<Map<String, Object>> backfillAlerts() {
        Map<String, Object> result = honeypotLogService.backfillAlertsFromHoneypotLogs();
        return ResponseEntity.ok(result);
    }

    @PostMapping("/logs")
    public ResponseEntity<HoneypotLog> addLog(@RequestBody Map<String, Object> logData) {
        try {
            log.info("Received honeypot log data: {}", logData);
            
            String sourceIp = (String) logData.get("sourceIp");
            String protocol = (String) logData.get("protocol");
            String attackType = (String) logData.get("attackType");
            String details = (String) logData.get("details");
            String timestamp = (String) logData.get("timestamp");
            Integer sourcePort = (Integer) logData.get("sourcePort");
            String severity = (String) logData.get("severity");
            String descriptionOverride = (String) logData.get("description");

            // Validate required fields
            if (sourceIp == null || protocol == null || attackType == null) {
                log.warn("Missing required fields in log data: {}", logData);
                return ResponseEntity.badRequest().build();
            }

            // Create payload from details
            String payload = details != null ? details : "No details provided";

            HoneypotLog honeypotLog = new HoneypotLog(sourceIp, protocol, attackType, payload);
            // Honour caller-supplied severity (LOW/MEDIUM/HIGH/CRITICAL); fall back to MEDIUM.
            // The map arc colour is driven off this field, so the default needs to stay neutral.
            honeypotLog.setSeverity(severity != null ? severity.toUpperCase() : "MEDIUM");
            // Prefer the caller-provided description, otherwise auto-format one.
            honeypotLog.setDescription(descriptionOverride != null ? descriptionOverride
                : String.format("Attack from %s:%d using %s protocol. %s",
                    sourceIp,
                    sourcePort != null ? sourcePort : 0,
                    protocol,
                    payload));
            
            // Set timestamp if provided
            if (timestamp != null) {
                try {
                    // Parse ISO timestamp format
                    java.time.LocalDateTime dateTime = java.time.LocalDateTime.parse(timestamp);
                    honeypotLog.setTimestamp(dateTime);
                } catch (Exception e) {
                    log.warn("Could not parse timestamp: {}, using current time", timestamp);
                }
            }
            
            log.info("Processing honeypot log: sourceIp={}, protocol={}, attackType={}", sourceIp, protocol, attackType);
            
            // Let the service apply blocking rules automatically
            HoneypotLog savedLog = honeypotLogService.saveLog(honeypotLog);
            log.info("Successfully saved honeypot log with ID: {}", savedLog.getId());
            
            return ResponseEntity.ok(savedLog);
        } catch (Exception e) {
            log.error("Error processing honeypot log: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(null);
        }
    }

    /**
     * Read-only health probe used by tunnels / external monitors to verify
     * the backend is up and the honeypot_logs table is reachable. Does NOT
     * insert any rows so it can be hit safely from a uptime checker without
     * polluting attacker statistics with a synthetic 192.168.x.x IP.
     */
    @GetMapping("/test")
    public ResponseEntity<Map<String, Object>> testEndpoint() {
        Map<String, Object> response = new HashMap<>();
        try {
            List<HoneypotLog> allLogs = honeypotLogService.getRecentLogs(1000);
            response.put("totalLogs", allLogs.size());
            response.put("databaseAccessible", true);
            response.put("sampleLogs", allLogs.stream().limit(5).map(l -> {
                Map<String, Object> logMap = new HashMap<>();
                logMap.put("id", l.getId());
                logMap.put("timestamp", l.getTimestamp());
                logMap.put("sourceIp", l.getSourceIp());
                logMap.put("protocol", l.getProtocol());
                logMap.put("attackType", l.getAttackType());
                logMap.put("isBlocked", l.getIsBlocked());
                return logMap;
            }).collect(Collectors.toList()));
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("error", e.getMessage());
            response.put("databaseAccessible", false);
            return ResponseEntity.status(500).body(response);
        }
    }

    /**
     * Ingest endpoint for remote Conpot sidecars (e.g. the Python forwarder
     * running on the GCP VM). Accepts either a single raw log line or a JSON
     * batch of log lines. Each line is parsed by ConpotLogIntegrationService —
     * source IP / protocol / credentials / etc. are extracted and persisted.
     *
     * Authentication: Bearer token in the Authorization header that must match
     * the honeypot.ingest.token property.
     *
     * Request body shapes accepted:
     *   1. {"line": "2026-04-25 ... New Modbus connection from 1.2.3.4..."}
     *   2. {"lines": ["...", "...", "..."]}
     *   3. Plain text body (single line) when Content-Type: text/plain
     */
    @PostMapping(value = "/ingest", consumes = {"application/json", "text/plain"})
    public ResponseEntity<Map<String, Object>> ingestLogs(
            @RequestHeader(value = "Authorization", required = false) String auth,
            @RequestHeader(value = "X-Decoy-Source", required = false) String decoySourceHeader,
            @RequestHeader(value = "X-HMI-Type",     required = false) String hmiTypeHeader,
            @RequestHeader(value = "X-HMI-Vendor",   required = false) String hmiVendorHeader,
            @RequestBody(required = false) Object body
    ) {
        if (ingestToken == null || ingestToken.isBlank()) {
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of(
                "ok", false,
                "error", "Ingest endpoint not configured: set honeypot.ingest.token in application.properties"
            ));
        }
        if (auth == null || !auth.equals("Bearer " + ingestToken)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of(
                "ok", false, "error", "missing or invalid bearer token"
            ));
        }

        List<String> lines = new java.util.ArrayList<>();
        try {
            if (body instanceof String) {
                String s = ((String) body).trim();
                if (!s.isEmpty()) lines.add(s);
            } else if (body instanceof Map<?, ?>) {
                Map<?, ?> m = (Map<?, ?>) body;
                Object single = m.get("line");
                Object batch = m.get("lines");
                if (single instanceof String && !((String) single).isBlank()) lines.add((String) single);
                if (batch instanceof List<?>) {
                    for (Object o : (List<?>) batch) {
                        if (o instanceof String && !((String) o).isBlank()) lines.add((String) o);
                    }
                }
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of(
                "ok", false, "error", "could not parse body: " + e.getMessage()
            ));
        }

        if (lines.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of(
                "ok", false, "error", "no log lines in request body"
            ));
        }

        boolean isInternalDecoy = "internal-decoy".equalsIgnoreCase(decoySourceHeader);

        int processed = 0, failed = 0;
        for (String line : lines) {
            try {
                if (isInternalDecoy) {
                    // Tripwire HMI inside an OT subnet — every connection is a
                    // CRITICAL incident. Bypass the heuristic parser and write
                    // a single high-confidence row tagged with the source/site.
                    persistInternalDecoyAlarm(line, hmiTypeHeader, hmiVendorHeader);
                } else {
                    // External honeypot (e.g. perimeter Conpot). Run the full
                    // parser pipeline that turns raw lines into rich rows.
                    conpotLogIntegrationService.processLogLine(line);
                    // Mirror to the in-memory ring buffer so the Live Stream
                    // WebSocket on the Conpot Monitor page sees it instantly.
                    if (conpotService != null) {
                        conpotService.appendLineForStreamOnly(line);
                    }
                }
                processed++;
            } catch (Exception e) {
                failed++;
                log.warn("Ingest: failed to process line '{}': {}", line, e.getMessage());
            }
        }

        Map<String, Object> resp = new HashMap<>();
        resp.put("ok", true);
        resp.put("received", lines.size());
        resp.put("processed", processed);
        resp.put("failed", failed);
        return ResponseEntity.ok(resp);
    }

    // Patterns used to extract structured data from a tripwire log line
    // Example payload coming from tripwire_hmi.py:
    //   [INTERNAL-DECOY] [WATER-PLANT-A] New Modbus connection from 172.30.50.250:48312.
    //   Tripwire HMI 'WATER_TREATMENT' on port 502 hit by lateral-movement actor (payload first bytes: 00010000...)
    private static final java.util.regex.Pattern TRIPWIRE_SITE =
        java.util.regex.Pattern.compile("\\[INTERNAL-DECOY\\]\\s*\\[([^\\]]+)\\]");
    private static final java.util.regex.Pattern TRIPWIRE_CONN =
        java.util.regex.Pattern.compile("New\\s+(\\w+)\\s+connection\\s+from\\s+(\\d{1,3}(?:\\.\\d{1,3}){3}):(\\d+)");
    private static final java.util.regex.Pattern TRIPWIRE_PORT =
        java.util.regex.Pattern.compile("on\\s+port\\s+(\\d+)");

    /**
     * Persist a single internal-decoy alarm row. Internal decoys live behind
     * the perimeter, so by definition any inbound connection is a CRITICAL
     * lateral-movement indicator: there is no legitimate reason to talk to a
     * tripwire HMI.
     */
    private void persistInternalDecoyAlarm(String line, String hmiTypeHeader, String hmiVendorHeader) {
        com.safetech.otshield.model.HoneypotLog row = new com.safetech.otshield.model.HoneypotLog();

        // Source IP + port
        java.util.regex.Matcher m = TRIPWIRE_CONN.matcher(line);
        String protoLabel = "UNKNOWN";
        if (m.find()) {
            protoLabel = m.group(1).toUpperCase();   // MODBUS / S7COMM / IEC104 / HTTP
            row.setSourceIp(m.group(2));
            try { row.setSourcePort(Integer.parseInt(m.group(3))); } catch (NumberFormatException ignored) {}
        }
        // Normalise protocol naming so it lines up with the rest of the dashboard
        if ("S7".equals(protoLabel)) protoLabel = "S7COMM";
        if ("IEC 104".equals(protoLabel) || "IEC-104".equals(protoLabel)) protoLabel = "IEC104";
        row.setProtocol(protoLabel);

        // Destination port — pulled from "on port NNN"
        java.util.regex.Matcher pm = TRIPWIRE_PORT.matcher(line);
        if (pm.find()) {
            try { row.setDestinationPort(Integer.parseInt(pm.group(1))); } catch (NumberFormatException ignored) {}
        }

        // Site tag — either from header or the inline [SITE-TAG] prefix
        java.util.regex.Matcher sm = TRIPWIRE_SITE.matcher(line);
        if (sm.find()) row.setSiteTag(sm.group(1));

        // Identification
        row.setDecoySource("internal-decoy");
        String hmiType = hmiTypeHeader != null && !hmiTypeHeader.isBlank() ? hmiTypeHeader : "HMI";
        String vendor  = hmiVendorHeader != null && !hmiVendorHeader.isBlank() ? hmiVendorHeader : "GENERIC";

        row.setSeverity("HIGH");
        row.setAttackType("Internal Decoy Tripwire");
        row.setDescription(String.format(
            "Lateral-movement probe hit %s tripwire HMI '%s' (%s) at site %s on port %s — %s",
            protoLabel, hmiType, vendor,
            row.getSiteTag() != null ? row.getSiteTag() : "OT-SUBNET",
            row.getDestinationPort() != null ? row.getDestinationPort().toString() : "?",
            line.length() > 200 ? line.substring(0, 200) + "..." : line));
        row.setPayload(line);
        row.setTimestamp(java.time.LocalDateTime.now());

        honeypotLogService.saveLog(row);
        log.info("Internal-decoy alarm persisted from tripwire: protocol={} src={} site={}",
            protoLabel, row.getSourceIp(), row.getSiteTag());

        // Mirror the tripwire hit onto the matching fake HMI card so the
        // deception UI's FakeHmisTab shows the real attacker IP, raises a
        // CRITICAL alarm on the alarm strip, and bumps the threat score.
        // This converts dummy "system start-up nominal" alarms into live
        // lateral-movement evidence sourced from the docker-compose fleet.
        if (fakeHmiService != null) {
            try {
                fakeHmiService.recordTripwireHit(
                    hmiType,
                    row.getSiteTag(),
                    vendor,
                    protoLabel,
                    row.getSourceIp(),
                    row.getSourcePort(),
                    row.getDestinationPort(),
                    line.length() > 64 ? line.substring(0, 64) + "…" : line
                );
            } catch (Exception e) {
                log.warn("FakeHmiService.recordTripwireHit failed (non-fatal): {}", e.getMessage());
            }
        }
    }
}
