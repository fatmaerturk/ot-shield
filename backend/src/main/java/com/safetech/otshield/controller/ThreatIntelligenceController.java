package com.safetech.otshield.controller;

import com.safetech.otshield.mapper.Threat;
import com.safetech.otshield.model.HoneypotLog;
import com.safetech.otshield.service.HoneypotLogService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * First-party ICS threat intelligence feed.
 *
 * Historically this endpoint returned a hardcoded list of 18 generic example
 * threats (with example.com logos). It now derives a REAL feed from the
 * platform's own honeypot/decoy telemetry: every external attacker that has
 * interacted with the OT decoy fabric becomes a threat entry, aggregated by
 * source IP with its protocols, techniques, severity, geolocation and
 * first/last-seen window. This is the product's core differentiator - threat
 * intelligence gathered first-hand from real ICS attackers, not a recycled
 * IT feed.
 *
 * The response shape (List&lt;Threat&gt;) is unchanged so the existing
 * ThreatIntelligence.tsx page consumes it without modification. The {@code source}
 * field carries the attacker IP (the UI's "Copy IP" / "VT Lookup" actions use it)
 * and {@code link} points to a VirusTotal lookup for that IP.
 */
@RestController
@RequestMapping("/api/threat-intel")
public class ThreatIntelligenceController {

    /** How many recent honeypot rows to aggregate the feed from. */
    private static final int SCAN_WINDOW = 2000;
    /** Max attacker entries returned. */
    private static final int MAX_ENTRIES = 150;

    private final HoneypotLogService honeypotLogService;

    public ThreatIntelligenceController(HoneypotLogService honeypotLogService) {
        this.honeypotLogService = honeypotLogService;
    }

    @GetMapping
    public List<Threat> getThreatIntel() {
        // Recent external attacker activity (internal-noise rows already filtered
        // out by getRecentLogs -> isInternalNoise).
        List<HoneypotLog> logs = honeypotLogService.getRecentLogs(SCAN_WINDOW);

        // Aggregate per attacker IP.
        Map<String, Agg> byIp = new LinkedHashMap<>();
        for (HoneypotLog l : logs) {
            String ip = l.getSourceIp();
            if (ip == null || ip.isBlank()) continue;
            byIp.computeIfAbsent(ip, Agg::new).add(l);
        }

        List<Threat> threats = new ArrayList<>();
        for (Agg a : byIp.values()) {
            threats.add(a.toThreat());
        }

        // Newest activity first, then cap.
        threats.sort(Comparator.comparing(Threat::getDate).reversed());
        if (threats.size() > MAX_ENTRIES) {
            return new ArrayList<>(threats.subList(0, MAX_ENTRIES));
        }
        return threats;
    }

    // ------------------------------------------------------------------
    //  Per-attacker aggregation
    // ------------------------------------------------------------------
    private static final class Agg {
        final String ip;
        int count = 0;
        int worstSeverity = 0;                 // 1=LOW .. 4=CRITICAL
        LocalDateTime firstSeen, lastSeen;
        String geo;
        String country;
        final Set<String> protocols = new LinkedHashSet<>();
        final Set<String> techniques = new LinkedHashSet<>();

        Agg(String ip) { this.ip = ip; }

        void add(HoneypotLog l) {
            count++;
            int rank = severityRank(l.getSeverity());
            if (rank > worstSeverity) worstSeverity = rank;

            LocalDateTime ts = l.getTimestamp();
            if (ts != null) {
                if (firstSeen == null || ts.isBefore(firstSeen)) firstSeen = ts;
                if (lastSeen == null || ts.isAfter(lastSeen)) lastSeen = ts;
            }
            if (l.getProtocol() != null && !l.getProtocol().isBlank()) protocols.add(l.getProtocol().toUpperCase());
            if (l.getAttackType() != null && !l.getAttackType().isBlank()) techniques.add(l.getAttackType());
            if (geo == null && l.getGeoLocation() != null && !l.getGeoLocation().isBlank()) geo = l.getGeoLocation();
            if (country == null && l.getCountry() != null && !l.getCountry().isBlank()) country = l.getCountry();
        }

        Threat toThreat() {
            String sevLabel = severityLabel(worstSeverity);
            String protoList = protocols.isEmpty() ? "unknown" : String.join(", ", protocols);
            String techList = techniques.isEmpty() ? "reconnaissance" : String.join(", ", techniques);

            String title;
            if (count > 1) {
                title = ip + " · " + count + " ICS attacks (" + protoList + ")";
            } else {
                title = (techniques.isEmpty() ? "ICS probe" : techniques.iterator().next())
                        + " · " + protoList + " from " + ip;
            }

            StringBuilder desc = new StringBuilder();
            desc.append(count).append(count == 1 ? " interaction" : " interactions")
                .append(" from ").append(ip);
            if (geo != null) desc.append(" (").append(geo).append(")");
            desc.append(". Protocols: ").append(protoList)
                .append(". Techniques: ").append(techList).append(".");
            if (firstSeen != null && lastSeen != null) {
                desc.append(" First seen ").append(firstSeen).append(", last seen ").append(lastSeen).append(".");
            }

            // Tags: severity first (UI derives level from this), then protocols and country.
            List<String> tags = new ArrayList<>();
            tags.add(sevLabel);
            tags.addAll(protocols);
            if (country != null) tags.add(country);

            String date = (lastSeen != null ? lastSeen : LocalDateTime.now()).toString();
            String link = "https://www.virustotal.com/gui/ip-address/" + ip;

            // NOTE: the UI uses `source` as the attacker IP (Copy IP / VT Lookup /
            // same-IP clustering all read th.source), so source must be the IP.
            return new Threat(ip, title, desc.toString(), ip, date, tags, "", link);
        }
    }

    private static int severityRank(String sev) {
        if (sev == null) return 1;
        switch (sev.toUpperCase()) {
            case "CRITICAL": return 4;
            case "HIGH":     return 3;
            case "MEDIUM":   return 2;
            default:         return 1; // LOW / unknown
        }
    }

    /** Map to the three labels the ThreatIntelligence UI filters on. */
    private static String severityLabel(int rank) {
        switch (rank) {
            case 4:  return "Critical";
            case 3:  return "High";
            default: return "Medium"; // MEDIUM and LOW both surface as Medium in the UI
        }
    }
}
