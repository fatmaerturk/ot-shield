package com.safetech.otshield.service;

import com.safetech.otshield.model.HoneypotLog;
import com.safetech.otshield.repository.HoneypotLogRepository;

import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
public class HoneypotLogService {

    private static final Logger log = LoggerFactory.getLogger(HoneypotLogService.class);

    private final HoneypotLogRepository honeypotLogRepository;
    private final BlockingRuleService blockingRuleService;
    private final GeoIpService geoIpService;

    /** Fans out persisted honeypot hits over SSE so the Attack Intelligence
     *  map animates one arc per real event. Optional to keep the save path
     *  decoupled from broadcast — a missing publisher is non-fatal. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private HoneypotEventPublisher eventPublisher;

    /** Optional — when present, every saved honeypot log produces a matching
     *  Alert row (subject to the severity floor in fanOutToAlert) so the
     *  Alerts page lights up alongside the Conpot Monitor. Wired as
     *  required=false so the honeypot pipeline keeps working even if the
     *  Alert subsystem is disabled or its tables aren't migrated yet. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    private com.safetech.otshield.repository.AlertRepository alertRepository;

    public HoneypotLogService(HoneypotLogRepository honeypotLogRepository,
                              BlockingRuleService blockingRuleService,
                              GeoIpService geoIpService) {
        this.honeypotLogRepository = honeypotLogRepository;
        this.blockingRuleService = blockingRuleService;
        this.geoIpService = geoIpService;
    }

    // =========================================================================
    //  Internal-noise filter
    // =========================================================================
    //
    // The honeypot_logs table accumulates several flavours of self-traffic
    // that aren't real attackers and would otherwise dominate the dashboard:
    //
    //   * Docker bridge gateway      172.17.0.1   (Conpot container reaching
    //                                              the forwarder via host)
    //   * Decoy compose gateway      172.30.50.1  (host -> tripwire HMIs in
    //                                              decoys/docker-compose.yml)
    //   * Localhost / loopback       127.0.0.0/8
    //   * Other RFC1918 ranges       10.0.0.0/8, 192.168.0.0/16
    //
    // These get hidden from public stats by isInternalNoise(). The ONE
    // exception is rows tagged decoySource = "internal-decoy": those are
    // tripwire hits and the attacker IP is the real lateral-movement signal,
    // even if it falls inside an RFC1918 range — so we keep them.

    /**
     * True when this log row is local infrastructure noise that should be
     * hidden from public attacker statistics. Tripwire (internal-decoy) rows
     * are always kept because their source IP is the lateral-movement signal.
     */
    public static boolean isInternalNoise(HoneypotLog l) {
        if (l == null) return false;
        if ("internal-decoy".equalsIgnoreCase(l.getDecoySource())) return false;
        return isInternalIp(l.getSourceIp());
    }

    /** True for RFC1918 / loopback / Docker-bridge ranges. Null/blank => true (treat as noise). */
    public static boolean isInternalIp(String ip) {
        if (ip == null || ip.isBlank()) return true;
        String s = ip.trim();
        if (s.equals("0.0.0.0") || s.startsWith("127.")) return true;
        // RFC1918
        if (s.startsWith("10.")) return true;
        if (s.startsWith("192.168.")) return true;
        // 172.16.0.0 - 172.31.255.255
        if (s.startsWith("172.")) {
            int second = parseOctet(s, 1);
            if (second >= 16 && second <= 31) return true;
        }
        return false;
    }

    private static int parseOctet(String ip, int index) {
        try {
            String[] parts = ip.split("\\.");
            if (parts.length <= index) return -1;
            return Integer.parseInt(parts[index]);
        } catch (Exception e) {
            return -1;
        }
    }

    // =========================================================================
    //  Reads
    // =========================================================================

    public List<HoneypotLog> getLogs(int page, int size, String sourceIp, String protocol) {
        List<HoneypotLog> allLogs = honeypotLogRepository.findAllByOrderByTimestampDesc().stream()
            .filter(l -> !isInternalNoise(l))
            .collect(Collectors.toList());

        if (sourceIp != null && !sourceIp.trim().isEmpty()) {
            allLogs = allLogs.stream()
                .filter(l -> l.getSourceIp() != null && l.getSourceIp().contains(sourceIp))
                .collect(Collectors.toList());
        }

        if (protocol != null && !protocol.trim().isEmpty()) {
            allLogs = allLogs.stream()
                .filter(l -> l.getProtocol() != null && l.getProtocol().equalsIgnoreCase(protocol))
                .collect(Collectors.toList());
        }

        int startIndex = page * size;
        int endIndex = Math.min(startIndex + size, allLogs.size());
        if (startIndex >= allLogs.size()) return new ArrayList<>();
        return allLogs.subList(startIndex, endIndex);
    }

    public List<HoneypotLog> getRecentLogs(int count) {
        return honeypotLogRepository.findAllByOrderByTimestampDesc().stream()
            .filter(l -> !isInternalNoise(l))
            .limit(count)
            .collect(Collectors.toList());
    }

    /**
     * Rich statistics endpoint consumed by the Attack Intelligence frontend.
     * Every field here is computed from the honeypot_logs table — no mock data.
     *
     * Internal-noise rows (Docker bridge / RFC1918 / loopback) are stripped
     * up-front so things like "top source IPs" and "country breakdown" reflect
     * real external attackers, not the host hitting its own decoy gateway.
     * Tripwire (internal-decoy) hits are kept because their attacker IP is
     * the actual lateral-movement signal.
     */
    public Map<String, Object> getStats() {
        List<HoneypotLog> rawLogs = honeypotLogRepository.findAll();
        List<HoneypotLog> allLogs = rawLogs.stream()
            .filter(l -> !isInternalNoise(l))
            .collect(Collectors.toList());
        Map<String, Object> stats = new HashMap<>();
        stats.put("filteredOutInternalNoise", rawLogs.size() - allLogs.size());

        int total = allLogs.size();
        stats.put("totalAttacks", total);

        // Unique IPs + sessions
        long uniqueIPs = allLogs.stream()
            .map(HoneypotLog::getSourceIp).filter(java.util.Objects::nonNull)
            .distinct().count();
        stats.put("uniqueIPs", uniqueIPs);

        long uniqueSessions = allLogs.stream()
            .map(HoneypotLog::getSessionId).filter(java.util.Objects::nonNull)
            .distinct().count();
        stats.put("uniqueSessions", uniqueSessions);

        // Protocol breakdown
        stats.put("attacksByProtocol", countBy(allLogs, HoneypotLog::getProtocol));

        // Severity breakdown (LOW / MEDIUM / HIGH)
        stats.put("attacksBySeverity", countBy(allLogs, HoneypotLog::getSeverity));

        // Attack type breakdown (Modbus Exploit, SQL Injection, Login Attempt, etc.)
        stats.put("attacksByType", countBy(allLogs, HoneypotLog::getAttackType));

        // Top source IPs with enrichment (country, last seen, severity)
        List<Map<String, Object>> topSourceIps = topAttackersEnriched(allLogs, 15);
        stats.put("topSourceIps", topSourceIps);

        // Country breakdown (from GeoIP-enriched logs)
        Map<String, Long> countryCounts = allLogs.stream()
            .map(HoneypotLog::getCountry)
            .filter(c -> c != null && !c.isBlank())
            .collect(Collectors.groupingBy(c -> c, Collectors.counting()));
        stats.put("countryBreakdown", sortDescAndLimit(countryCounts, 20));

        // City hotspots
        Map<String, Long> cityCounts = allLogs.stream()
            .filter(l -> l.getCity() != null && !l.getCity().isBlank())
            .collect(Collectors.groupingBy(l -> l.getCity() + ", " + (l.getCountry() != null ? l.getCountry() : ""), Collectors.counting()));
        stats.put("cityBreakdown", sortDescAndLimit(cityCounts, 10));

        // Credential intelligence
        Map<String, Long> usernames = allLogs.stream()
            .map(HoneypotLog::getUsernameAttempt)
            .filter(u -> u != null && !u.isBlank())
            .collect(Collectors.groupingBy(u -> u, Collectors.counting()));
        stats.put("topUsernames", sortDescAndLimit(usernames, 15));

        Map<String, Long> passwords = allLogs.stream()
            .map(HoneypotLog::getPasswordAttempt)
            .filter(p -> p != null && !p.isBlank())
            .collect(Collectors.groupingBy(p -> p, Collectors.counting()));
        stats.put("topPasswords", sortDescAndLimit(passwords, 15));

        // Destination ports targeted
        Map<Integer, Long> ports = allLogs.stream()
            .map(HoneypotLog::getDestinationPort)
            .filter(java.util.Objects::nonNull)
            .collect(Collectors.groupingBy(p -> p, Collectors.counting()));
        List<Map<String, Object>> topPorts = ports.entrySet().stream()
            .sorted(Map.Entry.<Integer, Long>comparingByValue().reversed())
            .limit(10)
            .map(e -> {
                Map<String, Object> m = new HashMap<>();
                m.put("port", e.getKey());
                m.put("count", e.getValue());
                m.put("service", portServiceName(e.getKey()));
                return m;
            })
            .collect(Collectors.toList());
        stats.put("topAttackedPorts", topPorts);

        // Hourly series (last 24h)
        stats.put("hourlySeries", hourlyBuckets(allLogs, 24));

        // Daily series (last 30d)
        stats.put("dailySeries", dailyBuckets(allLogs, 30));

        // OWASP Top 10 mapping
        stats.put("owaspMapping", owaspBreakdown(allLogs));

        // Windows
        LocalDateTime yesterday = LocalDateTime.now().minusHours(24);
        long recent24h = allLogs.stream()
            .filter(l -> l.getTimestamp() != null && l.getTimestamp().isAfter(yesterday))
            .count();
        stats.put("recentAttacks24h", recent24h);

        long blocked = allLogs.stream()
            .filter(l -> Boolean.TRUE.equals(l.getIsBlocked()))
            .count();
        stats.put("blockedAttacks", blocked);

        // External (perimeter Conpot) vs internal-decoy (tripwire HMI) split.
        // Internal-decoy events are inherently CRITICAL because no legitimate
        // user has any reason to talk to a tripwire — they signal lateral
        // movement, not internet noise.
        long internalDecoyCount = allLogs.stream()
            .filter(l -> "internal-decoy".equalsIgnoreCase(l.getDecoySource()))
            .count();
        long externalCount = allLogs.size() - internalDecoyCount;
        Map<String, Long> sourceSplit = new LinkedHashMap<>();
        sourceSplit.put("external", externalCount);
        sourceSplit.put("internal-decoy", internalDecoyCount);
        stats.put("decoySourceBreakdown", sourceSplit);

        // Per-site breakdown for the internal decoys (which OT site got hit?)
        Map<String, Long> bySite = allLogs.stream()
            .filter(l -> l.getSiteTag() != null && !l.getSiteTag().isBlank())
            .collect(Collectors.groupingBy(HoneypotLog::getSiteTag, Collectors.counting()));
        stats.put("internalDecoySiteBreakdown", sortDescAndLimit(bySite, 15));

        // Recent events (last 30 parsed rows) for the timeline feed
        List<Map<String, Object>> recentEvents = allLogs.stream()
            .sorted((a, b) -> {
                LocalDateTime ta = a.getTimestamp(), tb = b.getTimestamp();
                if (ta == null && tb == null) return 0;
                if (ta == null) return 1;
                if (tb == null) return -1;
                return tb.compareTo(ta);
            })
            .limit(30)
            .map(this::toEventMap)
            .collect(Collectors.toList());
        stats.put("recentEvents", recentEvents);

        stats.put("geoIpAvailable", geoIpService.isAvailable());
        return stats;
    }

    public List<Map<String, Object>> getAttackAttempts() {
        return honeypotLogRepository.findAllByOrderByTimestampDesc().stream()
            .filter(l -> !isInternalNoise(l))
            .limit(20)
            .map(this::toEventMap)
            .collect(Collectors.toList());
    }

    public void clearLogs() {
        honeypotLogRepository.deleteAll();
    }

    // =========================================================================
    //  Writes (every save enriches geolocation + applies blocking rules)
    // =========================================================================

    public HoneypotLog saveLog(HoneypotLog honeypotLog) {
        log.info("Saving honeypot log: sourceIp={}, protocol={}, attackType={}",
            honeypotLog.getSourceIp(), honeypotLog.getProtocol(), honeypotLog.getAttackType());

        enrichGeo(honeypotLog);

        try {
            boolean block = blockingRuleService.shouldBlock(honeypotLog);
            honeypotLog.setIsBlocked(block);
        } catch (Exception e) {
            log.error("Error applying blocking rules to log", e);
            honeypotLog.setIsBlocked(false);
        }

        HoneypotLog saved = honeypotLogRepository.save(honeypotLog);
        log.info("Saved honeypot log id={}", saved.getId());

        // Fan out to the Alerts subsystem so SOC analysts see honeypot hits on
        // the same dashboard as IDS / DPI / threat-intel events. Internal
        // noise is already filtered by the controller's persistInternalDecoyAlarm
        // path and isInternalNoise(), but we re-check here as a belt-and-braces
        // measure since saveLog is called from many places.
        try {
            fanOutToAlert(saved);
        } catch (Exception e) {
            // Never let alert fan-out break the honeypot save path.
            log.warn("Alert fan-out failed for honeypot log id={}: {}", saved.getId(), e.getMessage());
        }

        // Broadcast to map-animation SSE subscribers. Skip:
        //   - internal noise (Docker bridge / loopback) so self-traffic doesn't trigger arcs
        //   - logs that matched a block rule — the "Blocked" KPI then carries real meaning
        //     ("this attack was suppressed from the live feed"), instead of being a flag
        //     attached to a still-animated event.
        try {
            if (eventPublisher != null
                && !isInternalNoise(saved)
                && !Boolean.TRUE.equals(saved.getIsBlocked())) {
                eventPublisher.publish(saved);
            }
        } catch (Exception e) {
            log.debug("SSE publish skipped for honeypot log id={}: {}", saved.getId(), e.getMessage());
        }

        return saved;
    }

    /**
     * Convert a HoneypotLog row into an Alert and persist it. Skips:
     *   * internal-noise rows (RFC1918 / Docker bridge / loopback)
     *   * LOW severity rows that aren't from internal-decoys (would otherwise
     *     drown the Alerts page in random internet scan noise)
     */
    private void fanOutToAlert(HoneypotLog hp) {
        buildAlertFor(hp, /*skipDuplicateCheck=*/true);
    }

    /**
     * Build & persist an Alert for this honeypot log row. Returns true when a
     * new Alert was actually written, false when skipped (noise/LOW/duplicate).
     *
     * skipDuplicateCheck=true on the live save path (we already know it's a
     * brand-new log id), false on the backfill path (so re-running backfill
     * doesn't create duplicate alerts for honeypot rows that already have one).
     */
    private boolean buildAlertFor(HoneypotLog hp, boolean skipDuplicateCheck) {
        if (alertRepository == null) return false;
        if (isInternalNoise(hp)) return false;

        String sev = hp.getSeverity() == null ? "MEDIUM" : hp.getSeverity().toUpperCase();
        boolean isInternalDecoy = "internal-decoy".equalsIgnoreCase(hp.getDecoySource());

        // Severity floor: keep MEDIUM+ from external Conpot, but ALWAYS pass
        // tripwire (internal-decoy) hits since those are CRITICAL by definition
        // (lateral movement — there's no legitimate reason to talk to a tripwire).
        if (!isInternalDecoy && "LOW".equals(sev)) return false;

        // Idempotency: tag every honeypot-sourced alert with honeypot:<id>.
        // Backfill checks this tag so a row that already has an alert is
        // skipped on re-run, avoiding duplicates.
        String correlationTag = "honeypot:" + hp.getId();
        if (!skipDuplicateCheck) {
            try {
                List<com.safetech.otshield.model.Alert> existing = alertRepository.findByTag(correlationTag);
                if (existing != null && !existing.isEmpty()) return false;
            } catch (Exception e) {
                // If the tag table isn't ready yet, fall through and write —
                // it's better to risk a duplicate than to lose history.
                log.debug("findByTag failed (continuing): {}", e.getMessage());
            }
        }

        com.safetech.otshield.model.Alert a = new com.safetech.otshield.model.Alert();
        a.setTitle(buildAlertTitle(hp, isInternalDecoy));
        a.setDescription(hp.getDescription() != null ? hp.getDescription()
            : (hp.getAttackType() + " from " + hp.getSourceIp()));
        a.setSeverity(mapSeverity(sev, isInternalDecoy));
        a.setStatus(com.safetech.otshield.model.AlertStatus.NEW);
        a.setType(isInternalDecoy
            ? com.safetech.otshield.model.AlertType.HONEYPOT_EXPLOIT
            : com.safetech.otshield.model.AlertType.HONEYPOT_TRIGGER);
        a.setSource(isInternalDecoy ? "Tripwire/Decoy" : "ICS Decoy");
        a.setSourceIp(hp.getSourceIp());
        a.setSourcePort(hp.getSourcePort());
        a.setDestinationPort(hp.getDestinationPort());
        a.setProtocol(hp.getProtocol());
        a.setAcknowledged(false);
        a.setEscalated(false);
        a.setFalsePositive(false);
        a.setRiskScore(severityRank(sev) * 25);            // 25/50/75 for LOW/MED/HIGH
        a.setConfidenceScore(isInternalDecoy ? 95 : 70);   // tripwires are very high confidence
        a.setRawData(hp.getPayload());
        a.setTags(new ArrayList<>(Arrays.asList(
            correlationTag,
            "source:" + (isInternalDecoy ? "tripwire" : "conpot"),
            hp.getProtocol() != null ? "proto:" + hp.getProtocol().toLowerCase() : "proto:unknown"
        )));

        // Backfill path: copy the original honeypot timestamp so the Alert
        // appears in the right slot on the timeline instead of "just now".
        if (!skipDuplicateCheck && hp.getTimestamp() != null) {
            a.setCreatedAt(hp.getTimestamp());
            a.setUpdatedAt(hp.getTimestamp());
        }

        try {
            alertRepository.save(a);
            log.info("Alert fan-out: created alert for honeypot log id={} (sev={}, type={})",
                hp.getId(), a.getSeverity(), a.getType());
            return true;
        } catch (Exception e) {
            log.warn("Alert save failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Walk every existing honeypot_logs row and create an Alert for each one
     * that qualifies (skips noise + LOW external + rows that already have an
     * Alert tagged honeypot:&lt;id&gt;). Safe to re-run.
     *
     * Returns a small status map: { scanned, created, skipped }.
     */
    public Map<String, Object> backfillAlertsFromHoneypotLogs() {
        Map<String, Object> result = new HashMap<>();
        if (alertRepository == null) {
            result.put("ok", false);
            result.put("error", "AlertRepository not available");
            return result;
        }
        List<HoneypotLog> all = honeypotLogRepository.findAll();
        int scanned = all.size();
        int created = 0;
        int skipped = 0;
        for (HoneypotLog hp : all) {
            try {
                if (buildAlertFor(hp, /*skipDuplicateCheck=*/false)) created++;
                else skipped++;
            } catch (Exception e) {
                skipped++;
                log.warn("Backfill skipped honeypot id={} due to error: {}", hp.getId(), e.getMessage());
            }
        }
        result.put("ok", true);
        result.put("scanned", scanned);
        result.put("created", created);
        result.put("skipped", skipped);
        log.info("Backfill complete: scanned={}, created={}, skipped={}", scanned, created, skipped);
        return result;
    }

    private static String buildAlertTitle(HoneypotLog hp, boolean isInternalDecoy) {
        String proto = hp.getProtocol() != null ? hp.getProtocol() : "TCP";
        String ip    = hp.getSourceIp() != null ? hp.getSourceIp() : "unknown";
        if (isInternalDecoy) {
            return "Tripwire hit: " + proto + " probe from " + ip
                + (hp.getSiteTag() != null ? " @ " + hp.getSiteTag() : "");
        }
        String type = hp.getAttackType() != null ? hp.getAttackType() : "Honeypot interaction";
        return type + " · " + proto + " from " + ip;
    }

    /** Map our string severity ("LOW"/"MEDIUM"/"HIGH"/"CRITICAL") to the
     *  AlertSeverity enum, bumping internal-decoy rows up to CRITICAL since
     *  any tripwire hit is by definition a high-confidence incident. */
    private static com.safetech.otshield.mapper.AlertSeverity mapSeverity(String sev, boolean isInternalDecoy) {
        if (isInternalDecoy) return com.safetech.otshield.mapper.AlertSeverity.CRITICAL;
        switch (sev == null ? "MEDIUM" : sev.toUpperCase()) {
            case "CRITICAL": return com.safetech.otshield.mapper.AlertSeverity.CRITICAL;
            case "HIGH":     return com.safetech.otshield.mapper.AlertSeverity.HIGH;
            case "LOW":      return com.safetech.otshield.mapper.AlertSeverity.LOW;
            case "INFO":     return com.safetech.otshield.mapper.AlertSeverity.INFO;
            default:         return com.safetech.otshield.mapper.AlertSeverity.MEDIUM;
        }
    }

    public void logAttack(String sourceIp, String protocol, String attackType, String payload) {
        HoneypotLog l = new HoneypotLog(sourceIp, protocol, attackType, payload);
        l.setDescription("Attack detected from " + sourceIp + " using " + protocol);
        l.setSeverity("MEDIUM");
        saveLog(l);
    }

    public void logModbusAttack(String sourceIp, String payload) {
        HoneypotLog l = new HoneypotLog(sourceIp, "MODBUS", "Modbus Exploit", payload);
        l.setDescription("Modbus attack detected from " + sourceIp);
        l.setSeverity("HIGH");
        saveLog(l);
    }

    public void logHttpAttack(String sourceIp, String userAgent, String payload) {
        HoneypotLog l = new HoneypotLog(sourceIp, "HTTP", "HTTP Attack", payload);
        l.setUserAgent(userAgent);
        l.setDescription("HTTP attack from " + sourceIp + " with User-Agent: " + userAgent);
        l.setSeverity("MEDIUM");
        saveLog(l);
    }

    public void logS7CommAttack(String sourceIp, String payload) {
        HoneypotLog l = new HoneypotLog(sourceIp, "S7COMM", "S7Comm Exploit", payload);
        l.setDescription("S7Comm attack detected from " + sourceIp);
        l.setSeverity("HIGH");
        saveLog(l);
    }

    // =========================================================================
    //  Helpers
    // =========================================================================

    private void enrichGeo(HoneypotLog l) {
        try {
            if (l.getSourceIp() == null || l.getSourceIp().isBlank()) return;
            if (l.getCountry() != null && !l.getCountry().isBlank()) return; // already enriched
            GeoIpService.GeoInfo info = geoIpService.lookup(l.getSourceIp());
            if (info.country != null) l.setCountry(info.country);
            if (info.city != null) l.setCity(info.city);
            if (info.country != null) {
                String geo = info.city != null ? info.city + ", " + info.country : info.country;
                if (l.getGeoLocation() == null || l.getGeoLocation().isBlank()) {
                    l.setGeoLocation(geo);
                }
            }
        } catch (Exception e) {
            log.debug("GeoIP enrichment skipped: {}", e.getMessage());
        }
    }

    private static <T> Map<T, Long> countBy(List<HoneypotLog> logs, java.util.function.Function<HoneypotLog, T> keyFn) {
        return logs.stream()
            .map(keyFn).filter(java.util.Objects::nonNull)
            .collect(Collectors.groupingBy(k -> k, Collectors.counting()));
    }

    private static <K> LinkedHashMap<K, Long> sortDescAndLimit(Map<K, Long> m, int limit) {
        return m.entrySet().stream()
            .sorted(Map.Entry.<K, Long>comparingByValue().reversed())
            .limit(limit)
            .collect(Collectors.toMap(
                Map.Entry::getKey, Map.Entry::getValue,
                (a, b) -> a, LinkedHashMap::new));
    }

    private List<Map<String, Object>> topAttackersEnriched(List<HoneypotLog> logs, int limit) {
        // Do an IP→GeoInfo lookup once per unique attacker so we can ship lat/lon to the frontend
        Map<String, GeoIpService.GeoInfo> geoByIp = logs.stream()
            .map(HoneypotLog::getSourceIp).filter(java.util.Objects::nonNull).distinct()
            .collect(Collectors.toMap(ip -> ip, ip -> geoIpService.lookup(ip), (a, b) -> a));

        Map<String, List<HoneypotLog>> byIp = logs.stream()
            .filter(l -> l.getSourceIp() != null)
            .collect(Collectors.groupingBy(HoneypotLog::getSourceIp));

        return byIp.entrySet().stream()
            .sorted((a, b) -> Integer.compare(b.getValue().size(), a.getValue().size()))
            .limit(limit)
            .map(e -> {
                String ip = e.getKey();
                List<HoneypotLog> rows = e.getValue();
                Map<String, Object> m = new HashMap<>();
                m.put("ip", ip);
                m.put("count", rows.size());
                // Pull country/city from most recent row that has it
                String country = rows.stream().map(HoneypotLog::getCountry)
                    .filter(c -> c != null && !c.isBlank()).findFirst().orElse(null);
                String city = rows.stream().map(HoneypotLog::getCity)
                    .filter(c -> c != null && !c.isBlank()).findFirst().orElse(null);
                m.put("country", country);
                m.put("city", city);
                // lat/lon from MaxMind (preferred). Fall back to null if DB not available.
                GeoIpService.GeoInfo geo = geoByIp.getOrDefault(ip, GeoIpService.UNKNOWN);
                m.put("lat", geo.lat);
                m.put("lon", geo.lon);
                // Most common protocol for this attacker
                String topProto = rows.stream()
                    .map(HoneypotLog::getProtocol).filter(java.util.Objects::nonNull)
                    .collect(Collectors.groupingBy(p -> p, Collectors.counting()))
                    .entrySet().stream().max(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey).orElse(null);
                m.put("topProtocol", topProto);
                // Highest severity observed
                String worst = rows.stream()
                    .map(HoneypotLog::getSeverity).filter(java.util.Objects::nonNull)
                    .max((a, b) -> Integer.compare(severityRank(a), severityRank(b)))
                    .orElse(null);
                m.put("highestSeverity", worst);
                // Last seen
                LocalDateTime last = rows.stream()
                    .map(HoneypotLog::getTimestamp).filter(java.util.Objects::nonNull)
                    .max(LocalDateTime::compareTo).orElse(null);
                m.put("lastSeen", last != null ? last.toString() : null);
                // Blocked?
                boolean anyBlocked = rows.stream().anyMatch(r -> Boolean.TRUE.equals(r.getIsBlocked()));
                m.put("blocked", anyBlocked);
                return m;
            })
            .collect(Collectors.toList());
    }

    private static int severityRank(String s) {
        if (s == null) return 0;
        switch (s.toUpperCase()) {
            case "HIGH": case "CRITICAL": return 3;
            case "MEDIUM": return 2;
            case "LOW": return 1;
            default: return 0;
        }
    }

    private List<Map<String, Object>> hourlyBuckets(List<HoneypotLog> logs, int hours) {
        LocalDateTime now = LocalDateTime.now().withMinute(0).withSecond(0).withNano(0);
        LocalDateTime from = now.minusHours(hours - 1L);
        // Build ordered empty buckets
        List<Map<String, Object>> series = new ArrayList<>();
        Map<Long, Long[]> buckets = new LinkedHashMap<>();
        for (int i = 0; i < hours; i++) {
            LocalDateTime h = from.plusHours(i);
            buckets.put(h.toEpochSecond(java.time.ZoneOffset.UTC), new Long[]{0L, 0L, 0L, 0L}); // total, high, med, low
        }
        for (HoneypotLog l : logs) {
            if (l.getTimestamp() == null || l.getTimestamp().isBefore(from)) continue;
            LocalDateTime h = l.getTimestamp().withMinute(0).withSecond(0).withNano(0);
            Long key = h.toEpochSecond(java.time.ZoneOffset.UTC);
            Long[] cell = buckets.get(key);
            if (cell == null) continue;
            cell[0]++;
            int r = severityRank(l.getSeverity());
            if (r >= 3) cell[1]++;
            else if (r == 2) cell[2]++;
            else cell[3]++;
        }
        int i = 0;
        for (Map.Entry<Long, Long[]> e : buckets.entrySet()) {
            LocalDateTime h = from.plusHours(i++);
            Map<String, Object> point = new HashMap<>();
            point.put("hour", h.getHour());
            point.put("label", String.format("%02d:00", h.getHour()));
            point.put("total", e.getValue()[0]);
            point.put("high", e.getValue()[1]);
            point.put("medium", e.getValue()[2]);
            point.put("low", e.getValue()[3]);
            series.add(point);
        }
        return series;
    }

    private List<Map<String, Object>> dailyBuckets(List<HoneypotLog> logs, int days) {
        LocalDateTime now = LocalDateTime.now().toLocalDate().atStartOfDay();
        LocalDateTime from = now.minusDays(days - 1L);
        Map<String, Long> buckets = new LinkedHashMap<>();
        for (int i = 0; i < days; i++) {
            buckets.put(from.plusDays(i).toLocalDate().toString(), 0L);
        }
        for (HoneypotLog l : logs) {
            if (l.getTimestamp() == null || l.getTimestamp().isBefore(from)) continue;
            String key = l.getTimestamp().toLocalDate().toString();
            buckets.merge(key, 1L, Long::sum);
        }
        List<Map<String, Object>> series = new ArrayList<>();
        for (Map.Entry<String, Long> e : buckets.entrySet()) {
            Map<String, Object> p = new HashMap<>();
            p.put("date", e.getKey());
            p.put("count", e.getValue());
            series.add(p);
        }
        return series;
    }

    /** Static attack type -> OWASP Top 10 2021 mapping. */
    private Map<String, Object> owaspBreakdown(List<HoneypotLog> logs) {
        // Keys are OWASP categories; values are keywords to match in attackType/description
        Map<String, String[]> owasp = new LinkedHashMap<>();
        owasp.put("A01: Broken Access Control", new String[]{"unauthorized", "access", "privilege", "directory"});
        owasp.put("A02: Cryptographic Failures", new String[]{"crypto", "tls", "ssl"});
        owasp.put("A03: Injection", new String[]{"injection", "sql", "xss", "command"});
        owasp.put("A04: Insecure Design", new String[]{"design"});
        owasp.put("A05: Security Misconfiguration", new String[]{"misconfig", "default", "debug"});
        owasp.put("A06: Vulnerable Components", new String[]{"cve", "exploit", "vulnerable"});
        owasp.put("A07: Authentication Failures", new String[]{"login", "brute", "credential", "password", "auth"});
        owasp.put("A08: Software/Data Integrity", new String[]{"write", "firmware", "update", "integrity"});
        owasp.put("A09: Logging/Monitoring", new String[]{"log", "audit"});
        owasp.put("A10: SSRF", new String[]{"ssrf", "request forgery"});

        Map<String, Long> counts = new LinkedHashMap<>();
        for (String k : owasp.keySet()) counts.put(k, 0L);

        for (HoneypotLog l : logs) {
            String hay = ((l.getAttackType() != null ? l.getAttackType() : "") + " "
                        + (l.getDescription() != null ? l.getDescription() : "") + " "
                        + (l.getPayload() != null ? l.getPayload() : "")).toLowerCase();
            for (Map.Entry<String, String[]> e : owasp.entrySet()) {
                for (String kw : e.getValue()) {
                    if (hay.contains(kw)) {
                        counts.merge(e.getKey(), 1L, Long::sum);
                        break;
                    }
                }
            }
        }
        List<Map<String, Object>> list = new ArrayList<>();
        for (Map.Entry<String, Long> e : counts.entrySet()) {
            Map<String, Object> m = new HashMap<>();
            m.put("category", e.getKey());
            m.put("count", e.getValue());
            list.add(m);
        }
        Map<String, Object> out = new HashMap<>();
        out.put("breakdown", list);
        out.put("total", counts.values().stream().mapToLong(Long::longValue).sum());
        return out;
    }

    private Map<String, Object> toEventMap(HoneypotLog l) {
        Map<String, Object> m = new HashMap<>();
        m.put("id", l.getId());
        m.put("timestamp", l.getTimestamp() != null ? l.getTimestamp().toString() : null);
        m.put("sourceIp", l.getSourceIp());
        m.put("sourcePort", l.getSourcePort());
        m.put("destinationPort", l.getDestinationPort());
        m.put("protocol", l.getProtocol());
        m.put("attackType", l.getAttackType());
        m.put("severity", l.getSeverity());
        m.put("description", l.getDescription());
        m.put("country", l.getCountry());
        m.put("city", l.getCity());
        m.put("usernameAttempt", l.getUsernameAttempt());
        m.put("passwordAttempt", l.getPasswordAttempt());
        m.put("sessionId", l.getSessionId());
        m.put("isBlocked", l.getIsBlocked());
        m.put("decoySource", l.getDecoySource());
        m.put("siteTag", l.getSiteTag());
        return m;
    }

    private static final Map<Integer, String> PORT_SERVICES = new HashMap<>();
    static {
        PORT_SERVICES.put(22, "SSH");
        PORT_SERVICES.put(23, "Telnet");
        PORT_SERVICES.put(80, "HTTP");
        PORT_SERVICES.put(102, "S7Comm");
        PORT_SERVICES.put(161, "SNMP");
        PORT_SERVICES.put(443, "HTTPS");
        PORT_SERVICES.put(502, "Modbus");
        PORT_SERVICES.put(1911, "Niagara Fox");
        PORT_SERVICES.put(4840, "OPC UA");
        PORT_SERVICES.put(5020, "Modbus (mapped)");
        PORT_SERVICES.put(8800, "HTTP (Conpot)");
        PORT_SERVICES.put(8880, "HTTP (decoy)");
        PORT_SERVICES.put(20000, "DNP3");
        PORT_SERVICES.put(44818, "EtherNet/IP");
        PORT_SERVICES.put(47808, "BACnet");
        PORT_SERVICES.put(2404, "IEC 60870-5-104");
        PORT_SERVICES.put(10201, "S7Comm");
        PORT_SERVICES.put(16100, "SNMP (decoy)");
        PORT_SERVICES.put(6230, "IPMI");
        PORT_SERVICES.put(2121, "FTP (decoy)");
        PORT_SERVICES.put(6969, "TFTP (decoy)");
    }
    private static String portServiceName(Integer port) {
        if (port == null) return null;
        return PORT_SERVICES.getOrDefault(port, "Port " + port);
    }

    // Keep a reference to the Collections helpers we use:
    @SuppressWarnings("unused")
    private static final List<String> __keepImports = Arrays.asList("");
    @SuppressWarnings("unused")
    private static final ChronoUnit __unit = ChronoUnit.HOURS;
}
