package com.safetech.otshield.service;

import com.safetech.otshield.model.HoneypotLog;
import com.safetech.otshield.repository.HoneypotLogRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Computes attacker TTPs (Tactics, Techniques, Procedures) and behavioral
 * intelligence from collected honeypot logs. All numbers are derived from
 * the honeypot_logs table — no external feeds. The output drives the
 * "Attacker TTPs &amp; Behavioral Intel" tab on the Attack Intelligence page.
 */
@Service
public class TTPAnalysisService {

    private final HoneypotLogRepository repo;

    public TTPAnalysisService(HoneypotLogRepository repo) {
        this.repo = repo;
    }

    public Map<String, Object> buildTTPReport() {
        // Apply the same internal-noise filter used by /api/honeypot/stats so
        // the two endpoints agree on totals. Without this, RFC1918 / Docker
        // bridge / loopback / null-IP rows show up here and inflate the
        // numbers vs. the Overview tab. Tripwire (internal-decoy) rows are
        // intentionally kept because their attacker IP is real.
        List<HoneypotLog> logs = repo.findAllByOrderByTimestampDesc().stream()
            .filter(l -> !HoneypotLogService.isInternalNoise(l))
            .collect(Collectors.toList());
        Map<String, Object> out = new LinkedHashMap<>();

        out.put("totalEvents", logs.size());
        out.put("uniqueAttackers",
            logs.stream()
                .map(HoneypotLog::getSourceIp)
                .filter(Objects::nonNull)
                .distinct()
                .count());
        out.put("attackerProfiles", buildAttackerProfiles(logs));
        out.put("mitreTactics", buildMitreTactics(logs));
        out.put("toolFingerprints", buildToolFingerprints(logs));
        out.put("killChains", buildKillChains(logs));
        out.put("geoDistribution", buildGeoDistribution(logs));
        out.put("credentialIntelligence", buildCredentialIntelligence(logs));
        out.put("behavioralAnomalies", buildBehavioralAnomalies(logs));

        return out;
    }

    // ───────────────────────────────────────────────────────────
    // 1. ATTACKER PROFILES — per-IP behavior summary
    // ───────────────────────────────────────────────────────────
    private List<Map<String, Object>> buildAttackerProfiles(List<HoneypotLog> logs) {
        Map<String, List<HoneypotLog>> byIp = logs.stream()
            .filter(l -> l.getSourceIp() != null)
            .collect(Collectors.groupingBy(HoneypotLog::getSourceIp));

        List<Map<String, Object>> profiles = new ArrayList<>();
        for (Map.Entry<String, List<HoneypotLog>> e : byIp.entrySet()) {
            String ip = e.getKey();
            List<HoneypotLog> events = e.getValue();
            if (events.size() < 2) continue; // skip noise

            Set<String> protocols = events.stream()
                .map(HoneypotLog::getProtocol).filter(Objects::nonNull)
                .collect(Collectors.toCollection(TreeSet::new));
            Set<String> attackTypes = events.stream()
                .map(HoneypotLog::getAttackType).filter(Objects::nonNull)
                .collect(Collectors.toCollection(TreeSet::new));

            LocalDateTime first = events.stream().map(HoneypotLog::getTimestamp)
                .filter(Objects::nonNull).min(LocalDateTime::compareTo).orElse(null);
            LocalDateTime last = events.stream().map(HoneypotLog::getTimestamp)
                .filter(Objects::nonNull).max(LocalDateTime::compareTo).orElse(null);
            long activeMinutes = (first != null && last != null)
                ? ChronoUnit.MINUTES.between(first, last) : 0;

            String tier = scoreSophistication(events, protocols, attackTypes);
            String suspectedTool = guessTool(events);
            String country = events.stream()
                .map(HoneypotLog::getCountry).filter(Objects::nonNull)
                .findFirst().orElse(null);

            long credAttempts = events.stream()
                .filter(l -> l.getUsernameAttempt() != null || l.getPasswordAttempt() != null)
                .count();
            long highSev = events.stream()
                .filter(l -> "HIGH".equalsIgnoreCase(l.getSeverity())).count();

            Map<String, Object> p = new LinkedHashMap<>();
            p.put("sourceIp", ip);
            p.put("country", country);
            p.put("totalEvents", events.size());
            p.put("uniqueProtocols", protocols.size());
            p.put("protocols", new ArrayList<>(protocols));
            p.put("attackTypes", new ArrayList<>(attackTypes));
            p.put("credentialAttempts", credAttempts);
            p.put("highSeverityCount", highSev);
            p.put("firstSeen", first != null ? first.toString() : null);
            p.put("lastSeen", last != null ? last.toString() : null);
            p.put("activeMinutes", activeMinutes);
            p.put("sophistication", tier);
            p.put("suspectedTool", suspectedTool);
            profiles.add(p);
        }

        // Sort by total events desc
        profiles.sort((a, b) -> Integer.compare(
            (int) b.get("totalEvents"), (int) a.get("totalEvents")));

        return profiles;
    }

    /**
     * Heuristic sophistication scoring based on observed attacker behavior.
     * SCRIPT_KIDDIE: single protocol, no write attempts, brute-force only
     * INTERMEDIATE: 2 protocols OR write attempt OR sustained brute-force
     * ADVANCED: 3+ protocols OR ICS-write OR multi-tactic chain
     */
    private String scoreSophistication(List<HoneypotLog> events, Set<String> protos, Set<String> types) {
        boolean writeAttempt = types.stream().anyMatch(t ->
            t != null && (t.toLowerCase().contains("write") || t.toLowerCase().contains("control")));
        boolean icsProto = protos.stream().anyMatch(p ->
            Arrays.asList("MODBUS", "S7COMM", "IEC104", "DNP3", "ENIP", "BACNET").contains(p));
        boolean brute = types.stream().anyMatch(t ->
            t != null && t.toLowerCase().contains("brute"));
        int protoCount = protos.size();

        if (protoCount >= 3 || (writeAttempt && icsProto) || (icsProto && brute)) {
            return "ADVANCED";
        }
        if (protoCount == 2 || writeAttempt || brute) {
            return "INTERMEDIATE";
        }
        return "SCRIPT_KIDDIE";
    }

    // ───────────────────────────────────────────────────────────
    // 2. MITRE ATT&CK ICS TACTIC HEATMAP
    // ───────────────────────────────────────────────────────────
    private List<Map<String, Object>> buildMitreTactics(List<HoneypotLog> logs) {
        // tactic name -> [count, technique IDs set, attacker IPs set]
        Map<String, long[]> count = new LinkedHashMap<>();
        Map<String, Set<String>> techniques = new LinkedHashMap<>();
        Map<String, Set<String>> attackers = new LinkedHashMap<>();

        String[] tactics = {
            "Reconnaissance", "Initial Access", "Discovery",
            "Lateral Movement", "Collection", "Inhibit Response Function", "Impact"
        };
        for (String t : tactics) {
            count.put(t, new long[]{0});
            techniques.put(t, new TreeSet<>());
            attackers.put(t, new HashSet<>());
        }

        for (HoneypotLog l : logs) {
            String t = mapToTactic(l);
            if (t == null) continue;
            count.get(t)[0]++;
            techniques.get(t).add(mapToTechnique(l));
            if (l.getSourceIp() != null) attackers.get(t).add(l.getSourceIp());
        }

        List<Map<String, Object>> result = new ArrayList<>();
        for (String t : tactics) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("tactic", t);
            row.put("eventCount", count.get(t)[0]);
            row.put("techniques", new ArrayList<>(techniques.get(t)));
            row.put("uniqueAttackers", attackers.get(t).size());
            result.add(row);
        }
        return result;
    }

    /** Map a single honeypot log to one MITRE ICS tactic. */
    private String mapToTactic(HoneypotLog l) {
        String type = l.getAttackType() == null ? "" : l.getAttackType().toLowerCase();
        String desc = l.getDescription() == null ? "" : l.getDescription().toLowerCase();
        String proto = l.getProtocol() == null ? "" : l.getProtocol().toUpperCase();

        if (type.contains("write") || type.contains("control") || type.contains("command")) {
            return "Impact";
        }
        if (type.contains("brute") || type.contains("dictionary")) {
            return "Initial Access";
        }
        if (type.contains("login") || type.contains("auth")) {
            return "Initial Access";
        }
        if (type.contains("read") || type.contains("interrogation") || type.contains("discover")) {
            return "Discovery";
        }
        if (type.contains("scan") || desc.contains("scan") || type.contains("probe")) {
            return "Reconnaissance";
        }
        if (proto.equals("MODBUS") || proto.equals("S7COMM") || proto.equals("IEC104")
            || proto.equals("DNP3") || proto.equals("BACNET")) {
            return "Discovery";
        }
        if (proto.equals("HTTP") || proto.equals("FTP")) {
            return "Reconnaissance";
        }
        return null;
    }

    /** Map to a MITRE ICS technique ID (T08xx series). */
    private String mapToTechnique(HoneypotLog l) {
        String type = l.getAttackType() == null ? "" : l.getAttackType().toLowerCase();
        if (type.contains("brute")) return "T0812 Default Credentials";
        if (type.contains("write") || type.contains("control")) return "T0855 Unauthorized Command Message";
        if (type.contains("read") || type.contains("interrogation")) return "T0846 Remote System Discovery";
        if (type.contains("login") || type.contains("auth")) return "T0859 Valid Accounts";
        if (type.contains("exception")) return "T0858 Change Operating Mode (probe)";
        if (type.contains("scan") || type.contains("probe")) return "T0846 Remote System Discovery";
        return "T0840 Network Connection Enumeration";
    }

    // ───────────────────────────────────────────────────────────
    // 3. TOOL / WORDLIST FINGERPRINTING
    // ───────────────────────────────────────────────────────────
    private List<Map<String, Object>> buildToolFingerprints(List<HoneypotLog> logs) {
        Map<String, Long> ua = logs.stream()
            .map(HoneypotLog::getUserAgent)
            .filter(Objects::nonNull).filter(s -> !s.isBlank())
            .collect(Collectors.groupingBy(s -> s, Collectors.counting()));

        List<Map<String, Object>> tools = new ArrayList<>();

        // Tool inference from User-Agent + behavior
        Map<String, Long> toolCount = new LinkedHashMap<>();
        Map<String, Set<String>> toolIps = new LinkedHashMap<>();

        for (HoneypotLog l : logs) {
            String tool = guessTool(Collections.singletonList(l));
            if (tool == null || tool.equals("Unknown")) continue;
            toolCount.merge(tool, 1L, Long::sum);
            if (l.getSourceIp() != null) {
                toolIps.computeIfAbsent(tool, k -> new HashSet<>()).add(l.getSourceIp());
            }
        }

        for (Map.Entry<String, Long> e : toolCount.entrySet()) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("tool", e.getKey());
            row.put("eventCount", e.getValue());
            row.put("uniqueAttackers", toolIps.getOrDefault(e.getKey(), Collections.emptySet()).size());
            row.put("description", describeTool(e.getKey()));
            tools.add(row);
        }
        tools.sort((a, b) -> Long.compare((long) b.get("eventCount"), (long) a.get("eventCount")));

        Map<String, Object> uaTop = new LinkedHashMap<>();
        ua.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(10)
            .forEach(e -> uaTop.put(e.getKey(), e.getValue()));

        Map<String, Object> wrapper = new LinkedHashMap<>();
        wrapper.put("toolBreakdown", tools);
        wrapper.put("topUserAgents", uaTop);
        return Collections.singletonList(wrapper);
    }

    private String guessTool(List<HoneypotLog> events) {
        for (HoneypotLog l : events) {
            String ua = (l.getUserAgent() == null ? "" : l.getUserAgent()).toLowerCase();
            String type = (l.getAttackType() == null ? "" : l.getAttackType()).toLowerCase();
            String desc = (l.getDescription() == null ? "" : l.getDescription()).toLowerCase();

            if (ua.contains("mirai") || ua.contains("hajime") || ua.contains("gafgyt")) return "Mirai-class IoT botnet";
            if (ua.contains("nikto")) return "Nikto";
            if (ua.contains("nmap") || ua.contains("nse")) return "Nmap NSE";
            if (ua.contains("masscan") || ua.contains("zmap")) return "Mass scanner (masscan/zmap)";
            if (ua.contains("metasploit") || ua.contains("msf")) return "Metasploit";
            if (ua.contains("sqlmap")) return "sqlmap";
            if (ua.contains("hydra") || ua.contains("medusa")) return "Hydra/Medusa";
            if (ua.contains("dirb") || ua.contains("gobuster") || ua.contains("dirbuster")) return "Dir brute-forcer";
            if (ua.contains("python-requests") || ua.contains("python/")) return "Custom Python script";
            if (ua.contains("curl/")) return "Manual / curl";
            if (ua.contains("wget")) return "Manual / wget";
            if (ua.contains("shodan") || ua.contains("censys")) return "Shodan/Censys crawler";
            if (type.contains("brute")) return "Brute-force tool (Hydra-class)";
            if (type.contains("modbus") && desc.contains("function code")) return "Modbus client (pymodbus/msf)";
        }
        return "Unknown";
    }

    private String describeTool(String tool) {
        switch (tool) {
            case "Mirai-class IoT botnet":
                return "Default-credential IoT botnet — opportunistic, very high volume.";
            case "Nikto":
                return "Web vulnerability scanner — produces dense HTTP probe waves.";
            case "Nmap NSE":
                return "Service/version detection scanner with ICS scripts.";
            case "Mass scanner (masscan/zmap)":
                return "Internet-wide port scanner — pre-attack reconnaissance.";
            case "Metasploit":
                return "Exploitation framework — likely targeted operator.";
            case "sqlmap":
                return "SQL injection tester — web-app-focused attacker.";
            case "Hydra/Medusa":
                return "Credential brute-force tool.";
            case "Dir brute-forcer":
                return "Directory/path enumerator (dirb, gobuster, dirbuster).";
            case "Custom Python script":
                return "Custom tooling — possibly hand-rolled exploit / scraper.";
            case "Manual / curl":
                return "Hand-driven probing — likely a human investigator.";
            case "Manual / wget":
                return "Hand-driven probing — likely a human investigator.";
            case "Shodan/Censys crawler":
                return "Internet asset indexing service — passive recon.";
            case "Brute-force tool (Hydra-class)":
                return "Inferred from sustained credential attempts.";
            case "Modbus client (pymodbus/msf)":
                return "Direct Modbus library use — ICS-aware attacker.";
            default:
                return "Unrecognized tool signature.";
        }
    }

    // ───────────────────────────────────────────────────────────
    // 4. KILL CHAINS — per-attacker timeline of tactic progression
    // ───────────────────────────────────────────────────────────
    private List<Map<String, Object>> buildKillChains(List<HoneypotLog> logs) {
        Map<String, List<HoneypotLog>> byIp = logs.stream()
            .filter(l -> l.getSourceIp() != null)
            .collect(Collectors.groupingBy(HoneypotLog::getSourceIp));

        List<Map<String, Object>> chains = new ArrayList<>();
        for (Map.Entry<String, List<HoneypotLog>> e : byIp.entrySet()) {
            List<HoneypotLog> events = new ArrayList<>(e.getValue());
            if (events.size() < 3) continue;
            events.sort(Comparator.comparing(HoneypotLog::getTimestamp,
                Comparator.nullsLast(Comparator.naturalOrder())));

            // Build a sequence of distinct tactics as the IP progressed
            List<Map<String, Object>> steps = new ArrayList<>();
            String prevTactic = null;
            for (HoneypotLog l : events) {
                String tactic = mapToTactic(l);
                if (tactic == null) continue;
                if (tactic.equals(prevTactic)) continue;
                Map<String, Object> step = new LinkedHashMap<>();
                step.put("timestamp", l.getTimestamp() == null ? null : l.getTimestamp().toString());
                step.put("tactic", tactic);
                step.put("technique", mapToTechnique(l));
                step.put("protocol", l.getProtocol());
                step.put("attackType", l.getAttackType());
                steps.add(step);
                prevTactic = tactic;
                if (steps.size() > 12) break;
            }
            if (steps.size() < 2) continue;

            Map<String, Object> chain = new LinkedHashMap<>();
            chain.put("sourceIp", e.getKey());
            chain.put("totalEvents", events.size());
            chain.put("steps", steps);
            chains.add(chain);
        }

        // Top 10 most-active attackers' kill chains
        chains.sort((a, b) -> Integer.compare(
            (int) b.get("totalEvents"), (int) a.get("totalEvents")));
        return chains.size() > 10 ? chains.subList(0, 10) : chains;
    }

    // ───────────────────────────────────────────────────────────
    // 5. GEOGRAPHIC DISTRIBUTION
    // ───────────────────────────────────────────────────────────
    private List<Map<String, Object>> buildGeoDistribution(List<HoneypotLog> logs) {
        Map<String, long[]> byCountry = new LinkedHashMap<>(); // [events, uniqueIps]
        Map<String, Set<String>> ipsByCountry = new HashMap<>();

        for (HoneypotLog l : logs) {
            String c = l.getCountry();
            if (c == null || c.isBlank()) c = "Unknown";
            byCountry.computeIfAbsent(c, k -> new long[]{0})[0]++;
            if (l.getSourceIp() != null) {
                ipsByCountry.computeIfAbsent(c, k -> new HashSet<>()).add(l.getSourceIp());
            }
        }

        List<Map<String, Object>> rows = new ArrayList<>();
        for (Map.Entry<String, long[]> e : byCountry.entrySet()) {
            Map<String, Object> r = new LinkedHashMap<>();
            r.put("country", e.getKey());
            r.put("eventCount", e.getValue()[0]);
            r.put("uniqueAttackers", ipsByCountry.getOrDefault(e.getKey(), Collections.emptySet()).size());
            rows.add(r);
        }
        rows.sort((a, b) -> Long.compare((long) b.get("eventCount"), (long) a.get("eventCount")));
        return rows;
    }

    // ───────────────────────────────────────────────────────────
    // 6. CREDENTIAL INTELLIGENCE — wordlist family detection
    // ───────────────────────────────────────────────────────────
    private Map<String, Object> buildCredentialIntelligence(List<HoneypotLog> logs) {
        // Families inferred from credential overlap
        Set<String> miraiCreds = new HashSet<>(Arrays.asList(
            "root:root", "root:admin", "admin:admin", "root:xc3511", "root:vizxv",
            "root:888888", "root:xmhdipc", "root:default", "root:juantech", "root:123456",
            "support:support", "root:54321", "root:7ujMko0admin", "root:user",
            "root:realtek", "ubnt:ubnt", "guest:guest"
        ));
        Set<String> icsDefaults = new HashSet<>(Arrays.asList(
            "admin:admin", "siemens:siemens", "plc:plc", "operator:operator",
            "engineer:engineer", "factory:factory", "scada:scada", "hmi:hmi"
        ));

        Map<String, Long> attemptCounts = new LinkedHashMap<>();
        Map<String, Set<String>> attemptIps = new LinkedHashMap<>();
        long miraiHits = 0, icsHits = 0;
        Set<String> miraiAttackers = new HashSet<>();
        Set<String> icsAttackers = new HashSet<>();

        for (HoneypotLog l : logs) {
            String u = l.getUsernameAttempt();
            String p = l.getPasswordAttempt();
            if (u == null || p == null) continue;
            String pair = u + ":" + p;
            attemptCounts.merge(pair, 1L, Long::sum);
            if (l.getSourceIp() != null) {
                attemptIps.computeIfAbsent(pair, k -> new HashSet<>()).add(l.getSourceIp());
            }
            if (miraiCreds.contains(pair)) {
                miraiHits++;
                if (l.getSourceIp() != null) miraiAttackers.add(l.getSourceIp());
            }
            if (icsDefaults.contains(pair)) {
                icsHits++;
                if (l.getSourceIp() != null) icsAttackers.add(l.getSourceIp());
            }
        }

        List<Map<String, Object>> topPairs = new ArrayList<>();
        attemptCounts.entrySet().stream()
            .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
            .limit(15)
            .forEach(e -> {
                Map<String, Object> r = new LinkedHashMap<>();
                String[] up = e.getKey().split(":", 2);
                r.put("username", up[0]);
                r.put("password", up.length > 1 ? up[1] : "");
                r.put("attempts", e.getValue());
                r.put("uniqueAttackers", attemptIps.getOrDefault(e.getKey(), Collections.emptySet()).size());
                String family = miraiCreds.contains(e.getKey()) ? "Mirai/IoT botnet"
                    : icsDefaults.contains(e.getKey()) ? "ICS vendor default"
                    : "Generic dictionary";
                r.put("family", family);
                topPairs.add(r);
            });

        Map<String, Object> wrapper = new LinkedHashMap<>();
        wrapper.put("topCredentialPairs", topPairs);
        wrapper.put("miraiFamilyHits", miraiHits);
        wrapper.put("miraiAttackers", miraiAttackers.size());
        wrapper.put("icsDefaultHits", icsHits);
        wrapper.put("icsAttackers", icsAttackers.size());
        return wrapper;
    }

    // ───────────────────────────────────────────────────────────
    // 7. BEHAVIORAL ANOMALIES — burst, slow-low, multi-protocol pivot
    // ───────────────────────────────────────────────────────────
    private Map<String, Object> buildBehavioralAnomalies(List<HoneypotLog> logs) {
        Map<String, List<HoneypotLog>> byIp = logs.stream()
            .filter(l -> l.getSourceIp() != null && l.getTimestamp() != null)
            .collect(Collectors.groupingBy(HoneypotLog::getSourceIp));

        List<Map<String, Object>> burstAttackers = new ArrayList<>();
        List<Map<String, Object>> slowLowAttackers = new ArrayList<>();
        List<Map<String, Object>> pivotAttackers = new ArrayList<>();

        for (Map.Entry<String, List<HoneypotLog>> e : byIp.entrySet()) {
            String ip = e.getKey();
            List<HoneypotLog> events = e.getValue();
            if (events.size() < 3) continue;

            events.sort(Comparator.comparing(HoneypotLog::getTimestamp));
            LocalDateTime first = events.get(0).getTimestamp();
            LocalDateTime last = events.get(events.size() - 1).getTimestamp();
            long minutes = Math.max(1, ChronoUnit.MINUTES.between(first, last));
            double eventsPerMin = events.size() / (double) minutes;

            Set<String> protos = events.stream()
                .map(HoneypotLog::getProtocol).filter(Objects::nonNull)
                .collect(Collectors.toSet());

            // Burst — high event rate (>10 events/min sustained)
            if (eventsPerMin > 10 && events.size() >= 30) {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("sourceIp", ip);
                r.put("eventsPerMinute", Math.round(eventsPerMin * 10.0) / 10.0);
                r.put("totalEvents", events.size());
                r.put("note", "High-rate burst — automated tool / botnet.");
                burstAttackers.add(r);
            }
            // Slow-low — long active window with very low rate (suggests manual)
            if (minutes >= 60 && eventsPerMin < 1.0 && events.size() >= 5) {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("sourceIp", ip);
                r.put("activeMinutes", minutes);
                r.put("totalEvents", events.size());
                r.put("note", "Slow-and-low pattern — possible manual reconnaissance.");
                slowLowAttackers.add(r);
            }
            // Multi-protocol pivot — 3+ distinct protocols (ICS-aware)
            if (protos.size() >= 3) {
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("sourceIp", ip);
                r.put("protocols", new ArrayList<>(new TreeSet<>(protos)));
                r.put("totalEvents", events.size());
                r.put("note", "Pivots across multiple OT/IT protocols — ICS-aware operator.");
                pivotAttackers.add(r);
            }
        }

        burstAttackers.sort((a, b) -> Double.compare(
            (double) b.get("eventsPerMinute"), (double) a.get("eventsPerMinute")));
        slowLowAttackers.sort((a, b) -> Long.compare(
            (long) b.get("activeMinutes"), (long) a.get("activeMinutes")));
        pivotAttackers.sort((a, b) -> Integer.compare(
            ((List<?>) b.get("protocols")).size(), ((List<?>) a.get("protocols")).size()));

        Map<String, Object> wrapper = new LinkedHashMap<>();
        wrapper.put("burstAttackers", burstAttackers.size() > 10 ? burstAttackers.subList(0, 10) : burstAttackers);
        wrapper.put("slowLowAttackers", slowLowAttackers.size() > 10 ? slowLowAttackers.subList(0, 10) : slowLowAttackers);
        wrapper.put("multiProtocolPivots", pivotAttackers.size() > 10 ? pivotAttackers.subList(0, 10) : pivotAttackers);
        return wrapper;
    }
}
