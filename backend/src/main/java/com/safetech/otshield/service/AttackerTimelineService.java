package com.safetech.otshield.service;

import com.safetech.otshield.dto.attacker.*;
import com.safetech.otshield.model.Anomaly;
import com.safetech.otshield.model.Asset;
import com.safetech.otshield.model.Case;
import com.safetech.otshield.model.DpiEvent;
import com.safetech.otshield.model.HoneypotLog;
import com.safetech.otshield.repository.AnomalyRepository;
import com.safetech.otshield.repository.AssetRepository;
import com.safetech.otshield.repository.CaseRepository;
import com.safetech.otshield.repository.DpiEventRepository;
import com.safetech.otshield.repository.HoneypotLogRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Stitches every durable signal we hold for one attacker IP - internet-exposed
 * decoy hits, DPI events, anomalies (including decoy-twin trips), and opened
 * cases - into a single chronological kill-chain, each step mapped to a MITRE
 * ATT&amp;CK for ICS phase. 100% real first-party data: nothing is fabricated,
 * events come straight from the honeypot_logs / dpi_events / anomalies / cases
 * stores.
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class AttackerTimelineService {

    private static final int DPI_CAP = 500;      // per-attacker DPI rows pulled
    private static final int HONEYPOT_CAP = 150; // per-attacker decoy hits kept for the timeline (repetitive)
    private static final int DISPLAY_CAP = 150;  // max events returned for rendering (rollups use the full set)
    private static final int MIN_EVENTS_FOR_LIST = 1;

    private final HoneypotLogRepository honeypotLogRepository;
    private final AnomalyRepository anomalyRepository;
    private final DpiEventRepository dpiEventRepository;
    private final CaseRepository caseRepository;
    private final AssetRepository assetRepository;

    // ------------------------------------------------------------------
    // Single-attacker timeline
    // ------------------------------------------------------------------

    @Transactional(readOnly = true)
    public AttackerTimelineDTO getTimeline(String ip) {
        List<TimelineEventDTO> events = new ArrayList<>();
        String country = null;

        // 1) Internet-exposed decoy hits (repetitive - keep the most recent HONEYPOT_CAP)
        int honeypotKept = 0;
        for (HoneypotLog l : honeypotLogRepository.findBySourceIpOrderByTimestampDesc(ip)) {
            if (HoneypotLogService.isInternalNoise(l)) continue;
            if (country == null && l.getCountry() != null && !l.getCountry().isBlank()) {
                country = l.getCountry();
            }
            if (honeypotKept++ >= HONEYPOT_CAP) continue;
            String label = firstNonBlank(l.getAttackType(), "Decoy interaction");
            events.add(TimelineEventDTO.builder()
                    .timestamp(l.getTimestamp())
                    .source("HONEYPOT")
                    .phase(phaseOfHoneypot(l))
                    .title(label + " on internet-exposed decoy")
                    .description(l.getDescription())
                    .protocol(l.getProtocol())
                    .targetIp(l.getDestinationIp())
                    .severity(normalizeSeverity(l.getSeverity()))
                    .refId(l.getId() != null ? String.valueOf(l.getId()) : null)
                    .build());
        }

        // 2) DPI events where this IP was the source (pcap traffic)
        List<DpiEvent> dpi = dpiEventRepository
                .search(ip, null, null, null, null, null, null, PageRequest.of(0, DPI_CAP))
                .getContent();
        for (DpiEvent e : dpi) {
            boolean write = Boolean.TRUE.equals(e.getIsWrite());
            String fn = firstNonBlank(e.getFunctionName(), write ? "Write" : "Read");
            events.add(TimelineEventDTO.builder()
                    .timestamp(e.getEventTime())
                    .source("DPI")
                    .phase(phaseOfDpi(e))
                    .title(fn + (e.getDestinationIp() != null ? " -> " + e.getDestinationIp() : ""))
                    .description(e.getSummary())
                    .protocol(e.getProtocol())
                    .functionCode(e.getFunctionCode())
                    .targetIp(e.getDestinationIp())
                    .severity(write ? "HIGH" : "INFO")
                    .build());
        }

        // 3) Anomalies attributed to this IP (source field or twin-trip indicator)
        Map<String, Anomaly> anomalies = new LinkedHashMap<>();
        for (Anomaly a : anomalyRepository.findBySourceIp(ip)) anomalies.put(a.getId(), a);
        for (Anomaly a : anomalyRepository.findByIndicator("source:" + ip)) anomalies.putIfAbsent(a.getId(), a);
        for (Anomaly a : anomalies.values()) {
            events.add(TimelineEventDTO.builder()
                    .timestamp(a.getDetectedAt() != null ? a.getDetectedAt() : a.getCreatedAt())
                    .source("ANOMALY")
                    .phase(phaseOfAnomaly(a))
                    .title(a.getTitle())
                    .description(a.getDescription())
                    .protocol(a.getProtocol())
                    .targetIp(a.getDestinationIp())
                    .mitreId(a.getMitreId())
                    .mitreTechnique(a.getMitreTechnique())
                    .severity(a.getSeverity() != null ? a.getSeverity().name() : null)
                    .refId(a.getId())
                    .build());
        }

        // 4) Cases opened for this IP (src:<ip> / ip:<ip> tags)
        List<String> caseNumbers = new ArrayList<>();
        for (Case c : caseRepository.findAll()) {
            if (!caseMatchesIp(c, ip)) continue;
            caseNumbers.add(c.getCaseNumber());
            events.add(TimelineEventDTO.builder()
                    .timestamp(c.getCreatedAt())
                    .source("CASE")
                    .phase(KillChainPhase.IMPACT)
                    .title("Case " + c.getCaseNumber() + ": " + c.getTitle())
                    .severity(c.getSeverity() != null ? c.getSeverity().name() : null)
                    .refId(c.getCaseNumber())
                    .build());
        }

        // Chronological, oldest first; drop events without a timestamp to the end.
        events.sort(Comparator.comparing(TimelineEventDTO::getTimestamp,
                Comparator.nullsLast(Comparator.naturalOrder())));

        // Derived rollups
        LocalDateTime firstSeen = events.stream().map(TimelineEventDTO::getTimestamp)
                .filter(Objects::nonNull).min(Comparator.naturalOrder()).orElse(null);
        LocalDateTime lastSeen = events.stream().map(TimelineEventDTO::getTimestamp)
                .filter(Objects::nonNull).max(Comparator.naturalOrder()).orElse(null);

        List<KillChainPhase> reached = events.stream().map(TimelineEventDTO::getPhase)
                .filter(Objects::nonNull).distinct()
                .sorted(Comparator.comparingInt(KillChainPhase::ordinal))
                .collect(Collectors.toList());

        String highestSeverity = events.stream().map(TimelineEventDTO::getSeverity)
                .filter(Objects::nonNull).max(Comparator.comparingInt(AttackerTimelineService::severityRank))
                .orElse(null);

        List<TargetedAssetDTO> targeted = resolveTargets(events);

        // Cap the rendered list (rollups above already used the full set); keep
        // the most recent DISPLAY_CAP so a noisy attacker can't freeze the UI.
        List<TimelineEventDTO> display = events.size() > DISPLAY_CAP
                ? new ArrayList<>(events.subList(events.size() - DISPLAY_CAP, events.size()))
                : events;

        return AttackerTimelineDTO.builder()
                .ip(ip)
                .country(country)
                .firstSeen(firstSeen)
                .lastSeen(lastSeen)
                .totalEvents(events.size())
                .reachedPhases(reached)
                .highestSeverity(highestSeverity)
                .targetedAssets(targeted)
                .caseNumbers(caseNumbers)
                .events(display)
                .build();
    }

    // ------------------------------------------------------------------
    // Ranked "campaigns / top attackers" list
    // ------------------------------------------------------------------

    @Transactional(readOnly = true)
    public List<AttackerSummaryDTO> listAttackers(int limit) {
        Map<String, Agg> byIp = new HashMap<>();

        for (HoneypotLog l : honeypotLogRepository.findTop8000ByOrderByTimestampDesc()) {
            if (HoneypotLogService.isInternalNoise(l)) continue;
            if (l.getSourceIp() == null) continue;
            Agg a = byIp.computeIfAbsent(l.getSourceIp(), k -> new Agg());
            a.count++;
            a.touch(l.getTimestamp());
            if (a.country == null) a.country = l.getCountry();
            a.phases.add(phaseOfHoneypot(l));
            a.severities.add(normalizeSeverity(l.getSeverity()));
        }

        for (Anomaly an : anomalyRepository.findAll()) {
            if (an.getSourceIp() == null) continue;
            Agg a = byIp.computeIfAbsent(an.getSourceIp(), k -> new Agg());
            a.count++;
            a.touch(an.getDetectedAt() != null ? an.getDetectedAt() : an.getCreatedAt());
            KillChainPhase p = phaseOfAnomaly(an);
            a.phases.add(p);
            if (p == KillChainPhase.IMPACT) a.breached = true;
            if (an.getSeverity() != null) a.severities.add(an.getSeverity().name());
            if (an.getDestinationIp() != null) a.targets.add(an.getDestinationIp());
        }

        return byIp.entrySet().stream()
                .filter(e -> e.getValue().count >= MIN_EVENTS_FOR_LIST)
                .sorted((x, y) -> Integer.compare(y.getValue().count, x.getValue().count))
                .limit(Math.max(1, limit))
                .map(e -> {
                    Agg a = e.getValue();
                    return AttackerSummaryDTO.builder()
                            .ip(e.getKey())
                            .country(a.country)
                            .firstSeen(a.first)
                            .lastSeen(a.last)
                            .eventCount(a.count)
                            .reachedPhases(a.phases.stream()
                                    .sorted(Comparator.comparingInt(KillChainPhase::ordinal))
                                    .collect(Collectors.toList()))
                            .highestSeverity(a.severities.stream()
                                    .max(Comparator.comparingInt(AttackerTimelineService::severityRank))
                                    .orElse(null))
                            .targetedAssetCount(a.targets.size())
                            .breached(a.breached)
                            .build();
                })
                .collect(Collectors.toList());
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    /** Mutable per-IP accumulator for the ranked list. */
    private static final class Agg {
        int count;
        String country;
        boolean breached;
        LocalDateTime first;
        LocalDateTime last;
        final Set<KillChainPhase> phases = EnumSet.noneOf(KillChainPhase.class);
        final Set<String> severities = new HashSet<>();
        final Set<String> targets = new HashSet<>();

        void touch(LocalDateTime t) {
            if (t == null) return;
            if (first == null || t.isBefore(first)) first = t;
            if (last == null || t.isAfter(last)) last = t;
        }
    }

    private List<TargetedAssetDTO> resolveTargets(List<TimelineEventDTO> events) {
        Set<String> ips = events.stream()
                .map(TimelineEventDTO::getTargetIp)
                .filter(s -> s != null && !s.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
        List<TargetedAssetDTO> out = new ArrayList<>();
        for (String ip : ips) {
            Optional<Asset> asset = assetRepository.findByIpAddress(ip);
            out.add(TargetedAssetDTO.builder()
                    .ip(ip)
                    .name(asset.map(Asset::getName).orElse(null))
                    .purdueLevel(asset.map(a -> a.getPurdueLevel() != null ? a.getPurdueLevel().name() : null).orElse(null))
                    .protocol(asset.map(Asset::getProtocol).orElse(null))
                    .build());
        }
        return out;
    }

    private boolean caseMatchesIp(Case c, String ip) {
        if (c.getTags() == null) return false;
        return c.getTags().contains("src:" + ip) || c.getTags().contains("ip:" + ip);
    }

    /** MITRE technique id -> kill-chain phase, with a sensible default. */
    private KillChainPhase phaseOfAnomaly(Anomaly a) {
        String mitre = a.getMitreId() != null ? a.getMitreId().toUpperCase() : "";
        switch (mitre) {
            case "T0846": return KillChainPhase.RECON;            // Remote System Discovery
            case "T0883": return KillChainPhase.INITIAL_ACCESS;   // Internet Accessible Device
            case "T0836":                                          // Modify Parameter
            case "T0855": return KillChainPhase.IMPACT;           // Unauthorized Command Message
            default: break;
        }
        // Fall back to indicators / title keywords.
        String title = a.getTitle() != null ? a.getTitle().toLowerCase() : "";
        if (title.contains("write") || title.contains("burst")) return KillChainPhase.IMPACT;
        if (title.contains("scan") || title.contains("enumerat")) return KillChainPhase.RECON;
        if (title.contains("external") || title.contains("internet")) return KillChainPhase.INITIAL_ACCESS;
        return KillChainPhase.EXECUTION;
    }

    private KillChainPhase phaseOfDpi(DpiEvent e) {
        if (Boolean.TRUE.equals(e.getIsWrite())) return KillChainPhase.IMPACT;
        if (Boolean.TRUE.equals(e.getIsException())) return KillChainPhase.DISCOVERY;
        return KillChainPhase.DISCOVERY; // reads = probing the device
    }

    private KillChainPhase phaseOfHoneypot(HoneypotLog l) {
        String at = (l.getAttackType() != null ? l.getAttackType() : "").toLowerCase();
        String desc = (l.getDescription() != null ? l.getDescription() : "").toLowerCase();
        String blob = at + " " + desc;
        if (blob.contains("scan") || blob.contains("recon") || blob.contains("enumerat") || blob.contains("probe")) {
            return KillChainPhase.RECON;
        }
        if (blob.contains("write") || blob.contains("command") || blob.contains("modify")) {
            return KillChainPhase.IMPACT;
        }
        if (blob.contains("login") || blob.contains("credential") || blob.contains("auth") || blob.contains("brute")) {
            return KillChainPhase.EXECUTION;
        }
        // A hit on an internet-exposed decoy is, by definition, reaching an
        // internet-accessible device.
        return KillChainPhase.INITIAL_ACCESS;
    }

    private static int severityRank(String s) {
        if (s == null) return -1;
        switch (s.toUpperCase()) {
            case "CRITICAL": return 4;
            case "HIGH": return 3;
            case "MEDIUM": return 2;
            case "LOW": return 1;
            case "INFO": return 0;
            default: return -1;
        }
    }

    private static String normalizeSeverity(String s) {
        if (s == null || s.isBlank()) return null;
        return s.toUpperCase();
    }

    private static String firstNonBlank(String a, String fallback) {
        return (a != null && !a.isBlank()) ? a : fallback;
    }
}
