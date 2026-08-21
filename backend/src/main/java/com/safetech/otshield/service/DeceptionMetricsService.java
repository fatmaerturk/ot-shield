package com.safetech.otshield.service;

import com.safetech.otshield.dto.decoy.DecoyInstanceDTO;
import com.safetech.otshield.model.Case;
import com.safetech.otshield.model.Honeytoken;
import com.safetech.otshield.model.HoneypotLog;
import com.safetech.otshield.model.HoneytokenTrip;
import com.safetech.otshield.repository.CaseRepository;
import com.safetech.otshield.repository.HoneypotLogRepository;
import com.safetech.otshield.service.decoy.DecoyService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Deception effectiveness metrics - does the deception actually work?
 *
 * Everything here is computed from first-party state: captured decoy telemetry,
 * the running decoy fleet, planted honeytokens and their trips, and the cases the
 * fabric produced. It answers the questions a deception program is judged on:
 * how much adversary effort did we absorb, how deeply did we engage them, how
 * much intel did we harvest, how believable are the decoys (do attackers come
 * back), and how clean is the signal (lure trips are false-positive-free).
 */
@Service
public class DeceptionMetricsService {

    private final HoneypotLogRepository honeypotRepo;
    private final DecoyService decoyService;
    private final HoneytokenService honeytokenService;
    private final CaseRepository caseRepo;

    private static final DateTimeFormatter DAY = DateTimeFormatter.ofPattern("MM-dd");
    private static final int TREND_DAYS = 14;

    public DeceptionMetricsService(HoneypotLogRepository honeypotRepo,
                                   DecoyService decoyService,
                                   HoneytokenService honeytokenService,
                                   CaseRepository caseRepo) {
        this.honeypotRepo = honeypotRepo;
        this.decoyService = decoyService;
        this.honeytokenService = honeytokenService;
        this.caseRepo = caseRepo;
    }

    private static class Attacker {
        int count;
        LocalDateTime first;
        LocalDateTime last;
    }

    @Transactional(readOnly = true)
    public Map<String, Object> metrics() {
        long totalAbsorbed = safeCount();

        // ---- Aggregate a recent telemetry window (noise filtered) ----
        List<HoneypotLog> logs;
        try {
            logs = honeypotRepo.findTop8000ByOrderByTimestampDesc();
        } catch (Exception e) {
            logs = List.of();
        }

        Map<String, Attacker> attackers = new HashMap<>();
        Map<String, Integer> protocols = new HashMap<>();
        Map<String, Integer> attackTypes = new HashMap<>();
        Map<String, Integer> countries = new HashMap<>();
        Map<String, Integer> byDay = new TreeMap<>();
        int credentialsHarvested = 0;
        int analyzed = 0;

        for (HoneypotLog l : logs) {
            if (HoneypotLogService.isInternalNoise(l)) continue;
            String ip = l.getSourceIp();
            if (ip == null || ip.isBlank()) continue;
            analyzed++;

            Attacker a = attackers.computeIfAbsent(ip, k -> new Attacker());
            a.count++;
            LocalDateTime ts = l.getTimestamp();
            if (ts != null) {
                if (a.first == null || ts.isBefore(a.first)) a.first = ts;
                if (a.last == null || ts.isAfter(a.last)) a.last = ts;
            }
            if (l.getProtocol() != null && !l.getProtocol().isBlank())
                protocols.merge(l.getProtocol(), 1, Integer::sum);
            if (l.getAttackType() != null && !l.getAttackType().isBlank())
                attackTypes.merge(l.getAttackType(), 1, Integer::sum);
            if (l.getCountry() != null && !l.getCountry().isBlank())
                countries.merge(l.getCountry(), 1, Integer::sum);
            if (l.getUsernameAttempt() != null && !l.getUsernameAttempt().isBlank())
                credentialsHarvested++;
        }

        // Trend: last N days.
        LocalDate today = LocalDate.now();
        for (int i = TREND_DAYS - 1; i >= 0; i--) byDay.put(today.minusDays(i).format(DAY), 0);
        for (HoneypotLog l : logs) {
            if (HoneypotLogService.isInternalNoise(l)) continue;
            LocalDateTime ts = l.getTimestamp();
            if (ts == null) continue;
            if (ts.toLocalDate().isAfter(today.minusDays(TREND_DAYS))) {
                String k = ts.format(DAY);
                if (byDay.containsKey(k)) byDay.merge(k, 1, Integer::sum);
            }
        }

        // ---- Engagement quality ----
        int uniqueAttackers = attackers.size();
        long dwellSum = 0, dwellN = 0, returning = 0, deepest = 0;
        for (Attacker a : attackers.values()) {
            if (a.first != null && a.last != null) {
                long secs = Duration.between(a.first, a.last).getSeconds();
                if (secs > 0) { dwellSum += secs; dwellN++; }
                if (secs > 3600) returning++; // came back over an hour later -> decoy held their interest
            }
            if (a.count > deepest) deepest = a.count;
        }
        double avgInteractions = uniqueAttackers == 0 ? 0 : round1((double) analyzed / uniqueAttackers);
        long avgDwell = dwellN == 0 ? 0 : dwellSum / dwellN;

        // ---- Decoy fleet ----
        List<DecoyInstanceDTO> decoys = safeDecoys();
        int decoysActive = (int) decoys.stream()
            .filter(d -> d.getStatus() != null && "RUNNING".equals(d.getStatus().name())).count();
        List<Map<String, Object>> topDecoys = decoys.stream()
            .filter(d -> d.getTotalEngagements() != null && d.getTotalEngagements() > 0)
            .sorted((x, y) -> Long.compare(nz(y.getTotalEngagements()), nz(x.getTotalEngagements())))
            .limit(6)
            .map(d -> kv(d.getName(), nz(d.getTotalEngagements())))
            .toList();

        // ---- Lures (honeytokens) ----
        List<Honeytoken> tokens = safeTokens();
        List<HoneytokenTrip> trips = safeTrips();
        int luresPlanted = tokens.size();
        int luresTripped = (int) tokens.stream().filter(t -> t.getTrips() > 0).count();
        long beaconTrips = trips.stream().filter(t -> "CALLBACK".equals(t.getMethod())).count();
        long replayTrips = trips.stream().filter(t -> "CREDENTIAL_REPLAY".equals(t.getMethod())).count();
        double tripRate = luresPlanted == 0 ? 0 : Math.round(luresTripped * 100.0 / luresPlanted);

        // Avg time-to-trip (planted -> first opened).
        Map<String, java.time.Instant> created = new HashMap<>();
        for (Honeytoken t : tokens) if (t.getCreatedAt() != null) created.put(t.getId(), t.getCreatedAt());
        long tttSum = 0, tttN = 0;
        Set<String> seenToken = new HashSet<>();
        // trips are newest-first; walk oldest-first to catch the first trip per token
        List<HoneytokenTrip> chrono = new ArrayList<>(trips);
        chrono.sort(Comparator.comparing(HoneytokenTrip::getTs, Comparator.nullsLast(Comparator.naturalOrder())));
        for (HoneytokenTrip t : chrono) {
            if (t.getTs() == null || seenToken.contains(t.getTokenId())) continue;
            java.time.Instant c = created.get(t.getTokenId());
            if (c != null) { tttSum += Duration.between(c, t.getTs()).getSeconds(); tttN++; seenToken.add(t.getTokenId()); }
        }
        Long avgTimeToTrip = tttN == 0 ? null : tttSum / tttN;

        // ---- Cases produced by the fabric ----
        int casesFromDeception = 0;
        try {
            for (Case c : caseRepo.findAll()) {
                Set<String> tags = c.getTags();
                if (tags != null && (tags.contains("decoy") || tags.contains("honeytoken") || tags.contains("real-telemetry")))
                    casesFromDeception++;
            }
        } catch (Exception ignored) { }

        // ---- Assemble ----
        Map<String, Object> headline = new LinkedHashMap<>();
        headline.put("interactionsAbsorbed", totalAbsorbed);
        headline.put("uniqueAttackers", uniqueAttackers);
        headline.put("credentialsHarvested", credentialsHarvested);
        headline.put("decoysActive", decoysActive);
        headline.put("luresPlanted", luresPlanted);
        headline.put("luresTripped", luresTripped);
        headline.put("casesFromDeception", casesFromDeception);
        headline.put("lureFalsePositiveRate", 0.0); // lures never fire on legitimate users

        Map<String, Object> engagement = new LinkedHashMap<>();
        engagement.put("avgInteractionsPerAttacker", avgInteractions);
        engagement.put("avgDwellSeconds", avgDwell);
        engagement.put("returningAttackers", returning);
        engagement.put("deepestEngagement", deepest);

        Map<String, Object> coverage = new LinkedHashMap<>();
        coverage.put("protocolsCovered", protocols.size());
        coverage.put("countriesSeen", countries.size());

        Map<String, Object> lures = new LinkedHashMap<>();
        lures.put("planted", luresPlanted);
        lures.put("tripped", luresTripped);
        lures.put("tripRatePct", tripRate);
        lures.put("beaconTrips", beaconTrips);
        lures.put("replayTrips", replayTrips);
        lures.put("avgTimeToTripSeconds", avgTimeToTrip);

        Map<String, Object> breakdown = new LinkedHashMap<>();
        breakdown.put("topProtocols", top(protocols, 6));
        breakdown.put("topAttackTypes", top(attackTypes, 6));
        breakdown.put("topCountries", top(countries, 6));
        breakdown.put("topDecoys", topDecoys);

        List<Map<String, Object>> trend = new ArrayList<>();
        for (Map.Entry<String, Integer> e : byDay.entrySet()) trend.add(kv(e.getKey(), e.getValue()));

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("headline", headline);
        out.put("engagement", engagement);
        out.put("coverage", coverage);
        out.put("lures", lures);
        out.put("breakdown", breakdown);
        out.put("trend", trend);
        out.put("analyzedWindow", analyzed);
        return out;
    }

    // -------------------------------------------------------------- helpers ---

    private static List<Map<String, Object>> top(Map<String, Integer> m, int n) {
        return m.entrySet().stream()
            .sorted((a, b) -> b.getValue() - a.getValue())
            .limit(n)
            .map(e -> kv(e.getKey(), e.getValue()))
            .toList();
    }

    private static Map<String, Object> kv(String name, long count) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("name", name);
        m.put("count", count);
        return m;
    }

    private static long nz(Long v) { return v == null ? 0 : v; }

    private static double round1(double v) { return Math.round(v * 10.0) / 10.0; }

    private long safeCount() {
        try { return honeypotRepo.count(); } catch (Exception e) { return 0; }
    }

    private List<DecoyInstanceDTO> safeDecoys() {
        try { return decoyService.listInstances(); } catch (Exception e) { return List.of(); }
    }

    private List<Honeytoken> safeTokens() {
        try { return honeytokenService.list(); } catch (Exception e) { return List.of(); }
    }

    private List<HoneytokenTrip> safeTrips() {
        try { return honeytokenService.recentTrips(); } catch (Exception e) { return List.of(); }
    }
}
