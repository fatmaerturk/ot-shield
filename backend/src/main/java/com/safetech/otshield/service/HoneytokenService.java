package com.safetech.otshield.service;

import com.safetech.otshield.dto.cases.CreateCaseRequest;
import com.safetech.otshield.mapper.AlertSeverity;
import com.safetech.otshield.model.CaseCategory;
import com.safetech.otshield.model.CasePriority;
import com.safetech.otshield.model.Honeytoken;
import com.safetech.otshield.model.HoneypotLog;
import com.safetech.otshield.model.HoneytokenTrip;
import com.safetech.otshield.repository.HoneypotLogRepository;
import com.safetech.otshield.repository.HoneytokenRepository;
import com.safetech.otshield.repository.HoneytokenTripRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;

/**
 * Manages honeytokens (decoy lures) and turns a trip into a high-confidence
 * incident. A trip fires through two REAL mechanisms:
 *
 *  1. CALLBACK - a planted beacon URL/document is opened; the hit endpoint feeds
 *     the real source IP + user agent here.
 *  2. CREDENTIAL_REPLAY - a planted secret surfaces in captured decoy telemetry
 *     (an attacker harvested it and replayed it against the decoy fabric). A
 *     scheduled scan correlates each token's match string against the honeypot
 *     credential attempts / payloads.
 *
 * Every trip auto-opens a SOC case, closing the loop from lure to tracked
 * incident (and NIS2 evidence).
 */
@Service
public class HoneytokenService {

    private static final Logger log = LoggerFactory.getLogger(HoneytokenService.class);

    private final HoneytokenRepository tokenRepo;
    private final HoneytokenTripRepository tripRepo;
    private final HoneypotLogRepository honeypotRepo;
    private final CaseService caseService;

    public HoneytokenService(HoneytokenRepository tokenRepo,
                             HoneytokenTripRepository tripRepo,
                             HoneypotLogRepository honeypotRepo,
                             CaseService caseService) {
        this.tokenRepo = tokenRepo;
        this.tripRepo = tripRepo;
        this.honeypotRepo = honeypotRepo;
        this.caseService = caseService;
    }

    // ---------------------------------------------------------------- CRUD ---

    public List<Honeytoken> list() {
        return tokenRepo.findAllByOrderByCreatedAtDesc();
    }

    /** Generate a new honeytoken of the given type with a believable payload. */
    public Honeytoken create(String type, String label, String note) {
        String t = (type == null ? "URL_BEACON" : type.trim().toUpperCase());
        String id = rand(24);
        String tokenValue;
        String matchValue;

        switch (t) {
            case "CREDENTIAL": {
                String user = "svc-scada-" + rand(4).toLowerCase();
                String pass = rand(12);
                tokenValue = user + " / " + pass;
                matchValue = user; // an attacker replays this exact username
                break;
            }
            case "API_KEY": {
                String key = "otsk_live_" + rand(28).toLowerCase();
                tokenValue = key;
                matchValue = key;
                break;
            }
            case "CONNECTION_STRING": {
                String pass = rand(12);
                tokenValue = "Server=hist-db01;Database=scada_historian;Uid=report_ro;Pwd=" + pass + ";";
                matchValue = "report_ro"; // the distinctive account name
                break;
            }
            case "FILE_BEACON": {
                // A fake engineering document that beacons home when opened.
                tokenValue = "PLC_Backup_" + rand(4).toLowerCase() + ".pdf (embeds beacon /api/honeytoken/hit/" + id + ")";
                matchValue = null; // trips only via callback
                break;
            }
            case "URL_BEACON":
            default: {
                t = "URL_BEACON";
                tokenValue = "/api/honeytoken/hit/" + id; // planted as a bookmark / link
                matchValue = null;
                break;
            }
        }

        Honeytoken token = Honeytoken.builder()
            .id(id)
            .type(t)
            .label(label == null || label.isBlank() ? "unspecified location" : label.trim())
            .note(note)
            .tokenValue(tokenValue)
            .matchValue(matchValue)
            .createdAt(Instant.now())
            .trips(0)
            .build();
        return tokenRepo.save(token);
    }

    public boolean delete(String id) {
        if (!tokenRepo.existsById(id)) return false;
        tokenRepo.deleteById(id);
        return true;
    }

    public List<HoneytokenTrip> recentTrips() {
        return tripRepo.findTop200ByOrderByTsDesc();
    }

    public Map<String, Object> stats() {
        List<Honeytoken> all = tokenRepo.findAll();
        long tripped = all.stream().filter(h -> h.getTrips() > 0).count();
        List<HoneytokenTrip> trips = tripRepo.findTop200ByOrderByTsDesc();
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("totalTokens", all.size());
        m.put("trippedTokens", tripped);
        m.put("totalTrips", trips.size());
        m.put("lastTrippedAt", trips.isEmpty() ? null : trips.get(0).getTs());
        return m;
    }

    // ------------------------------------------------------------- Tripping ---

    /** A planted beacon URL/document was hit - the strongest, fully-real signal. */
    public boolean recordCallbackHit(String id, String sourceIp, String userAgent, String referer) {
        Honeytoken token = tokenRepo.findById(id).orElse(null);
        if (token == null) return false; // unknown id: stay quiet, don't leak
        String detail = "Planted lure opened from " + sourceIp
            + (referer != null && !referer.isBlank() ? " (referer: " + referer + ")" : "");
        fireTrip(token, "CALLBACK", sourceIp, userAgent, detail);
        return true;
    }

    /**
     * Scheduled correlation: does any planted secret appear in captured decoy
     * telemetry? If so, an attacker harvested and replayed it - a real breach
     * signal grounded in first-party data.
     */
    @Scheduled(fixedDelay = 60000, initialDelay = 20000)
    public void scanCredentialReplays() {
        List<Honeytoken> tokens = tokenRepo.findAll();
        boolean anyMatchable = tokens.stream().anyMatch(t -> t.getMatchValue() != null);
        if (!anyMatchable) return;

        List<HoneypotLog> logs;
        try {
            logs = honeypotRepo.findTop8000ByOrderByTimestampDesc();
        } catch (Exception e) {
            return;
        }

        for (HoneypotLog l : logs) {
            String ip = l.getSourceIp();
            if (ip == null || ip.isBlank()) continue;
            String user = safeLower(l.getUsernameAttempt());
            String pass = safeLower(l.getPasswordAttempt());
            String payload = safeLower(l.getPayload());

            for (Honeytoken token : tokens) {
                String mv = token.getMatchValue();
                if (mv == null || mv.isBlank()) continue;
                String needle = mv.toLowerCase();
                boolean hit = (user != null && user.equals(needle))
                    || (pass != null && pass.equals(needle))
                    || (payload != null && payload.contains(needle));
                if (!hit) continue;
                // One trip per (token, attacker) for this method - avoid re-firing.
                if (tripRepo.existsByTokenIdAndSourceIpAndMethod(token.getId(), ip, "CREDENTIAL_REPLAY")) continue;
                fireTrip(token, "CREDENTIAL_REPLAY", ip,
                    l.getProtocol() == null ? null : (l.getProtocol() + " probe"),
                    "Planted " + token.getType() + " ('" + mv + "') replayed against the decoy fabric from " + ip);
            }
        }
    }

    /** Record the trip, bump the token, and open a SOC case. */
    private void fireTrip(Honeytoken token, String method, String sourceIp, String userAgent, String detail) {
        HoneytokenTrip trip = HoneytokenTrip.builder()
            .tokenId(token.getId())
            .tokenLabel(token.getLabel())
            .tokenType(token.getType())
            .method(method)
            .sourceIp(sourceIp)
            .userAgent(userAgent)
            .detail(detail)
            .ts(Instant.now())
            .build();
        tripRepo.save(trip);

        token.setTrips(token.getTrips() + 1);
        token.setLastTrippedAt(trip.getTs());
        token.setLastSourceIp(sourceIp);
        tokenRepo.save(token);

        openCase(token, trip);
        log.warn("Honeytoken TRIP [{}] {} planted at '{}' by {}", method, token.getType(), token.getLabel(), sourceIp);
    }

    private void openCase(Honeytoken token, HoneytokenTrip trip) {
        try {
            Set<String> tags = new LinkedHashSet<>();
            tags.add("honeytoken");
            tags.add("lure");
            tags.add("deception");
            tags.add("method:" + trip.getMethod().toLowerCase());
            tags.add("type:" + token.getType().toLowerCase());
            if (trip.getSourceIp() != null) tags.add("ip:" + trip.getSourceIp());

            String description = "A planted honeytoken was used - a high-confidence breach signal "
                + "(no legitimate user has any reason to touch a decoy lure).\n\n"
                + "Token type: " + token.getType() + "\n"
                + "Planted at: " + token.getLabel() + "\n"
                + "Trip method: " + trip.getMethod() + "\n"
                + "Source: " + trip.getSourceIp() + "\n"
                + (trip.getUserAgent() != null ? "User agent: " + trip.getUserAgent() + "\n" : "")
                + "\n" + trip.getDetail();

            CreateCaseRequest req = CreateCaseRequest.builder()
                .title("Honeytoken tripped: " + token.getType() + " @ " + token.getLabel())
                .description(description)
                .priority(CasePriority.CRITICAL)
                .severity(AlertSeverity.HIGH)
                .category(CaseCategory.UNAUTHORIZED_ACCESS)
                .reporterName("OTShield Deception")
                .tags(tags)
                .build();
            caseService.create(req);
        } catch (Exception e) {
            log.warn("Honeytoken trip case creation failed: {}", e.getMessage());
        }
    }

    // -------------------------------------------------------------- helpers ---

    private static String safeLower(String s) {
        return s == null ? null : s.trim().toLowerCase();
    }

    /** URL-safe random token of n chars (no Math.random / SecureRandom seeding issues at build time). */
    private static String rand(int n) {
        StringBuilder sb = new StringBuilder(n);
        while (sb.length() < n) {
            sb.append(UUID.randomUUID().toString().replace("-", ""));
        }
        return sb.substring(0, n);
    }
}
