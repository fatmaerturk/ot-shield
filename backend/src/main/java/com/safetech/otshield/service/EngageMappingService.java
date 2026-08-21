package com.safetech.otshield.service;

import com.safetech.otshield.dto.decoy.DecoyActionResultDTO;
import com.safetech.otshield.dto.decoy.DecoyInstanceDTO;
import com.safetech.otshield.model.Honeytoken;
import com.safetech.otshield.model.HoneytokenTrip;
import com.safetech.otshield.model.HoneypotLog;
import com.safetech.otshield.repository.CaseRepository;
import com.safetech.otshield.repository.HoneypotLogRepository;
import com.safetech.otshield.service.decoy.DecoyService;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * MITRE Engage mapping - the defensive complement to ATT&CK.
 *
 * ATT&CK describes what the adversary does; Engage describes the deception and
 * adversary-engagement techniques the defender applies against them. This
 * service maps OTShield's live deception program onto the Engage taxonomy
 * (Prepare, Expose, Elicit, Affect, Understand) and marks each activity ACTIVE
 * or AVAILABLE from REAL state: decoys running, honeytokens planted and tripped,
 * telemetry collected, response actions taken, cases opened. The result is a
 * coverage view that shows - with first-party evidence - which defensive
 * deception techniques the platform is actually exercising.
 *
 * Activity and goal names follow the public MITRE Engage matrix; statuses and
 * evidence counts are computed from this deployment.
 */
@Service
public class EngageMappingService {

    private final DecoyService decoyService;
    private final HoneytokenService honeytokenService;
    private final HoneypotLogRepository honeypotRepo;
    private final CaseRepository caseRepo;

    public EngageMappingService(DecoyService decoyService,
                                HoneytokenService honeytokenService,
                                HoneypotLogRepository honeypotRepo,
                                CaseRepository caseRepo) {
        this.decoyService = decoyService;
        this.honeytokenService = honeytokenService;
        this.honeypotRepo = honeypotRepo;
        this.caseRepo = caseRepo;
    }

    /** The five Engage strategic goals, in matrix order. */
    private static final List<String> GOALS =
        List.of("Prepare", "Expose", "Elicit", "Affect", "Understand");

    public Map<String, Object> buildMatrix() {
        // ---- Gather real state once ----
        List<DecoyInstanceDTO> decoys = safe(() -> decoyService.listInstances(), List.of());
        List<Honeytoken> tokens = safe(() -> honeytokenService.list(), List.of());
        List<HoneytokenTrip> trips = safe(() -> honeytokenService.recentTrips(), List.of());
        List<DecoyActionResultDTO> actions = safe(() -> decoyService.recentActions(200), List.of());

        long events = safe(honeypotRepo::count, 0L);
        long cases = safe(caseRepo::count, 0L);

        int decoysRunning = (int) decoys.stream()
            .filter(d -> d.getStatus() != null && "RUNNING".equals(d.getStatus().name())).count();
        int internalDecoys = (int) decoys.stream().filter(d -> id(d).startsWith("int-")).count();
        int externalDecoys = (int) decoys.stream().filter(d -> id(d).startsWith("ext-")).count();
        long distinctProtocols = decoys.stream()
            .map(d -> d.getProtocol() == null ? "?" : d.getProtocol().name()).distinct().count();
        long personas = decoys.stream()
            .map(d -> nn(vendor(d)) + "|" + nn(model(d))).distinct().count();

        long beaconTokens = tokens.stream()
            .filter(t -> "URL_BEACON".equals(t.getType()) || "FILE_BEACON".equals(t.getType())).count();
        long credentialTokens = tokens.stream()
            .filter(t -> "CREDENTIAL".equals(t.getType()) || "API_KEY".equals(t.getType())).count();
        long contentTokens = tokens.stream()
            .filter(t -> "CONNECTION_STRING".equals(t.getType())).count();
        long beaconTrips = trips.stream().filter(t -> "CALLBACK".equals(t.getMethod())).count();
        long replayTrips = trips.stream().filter(t -> "CREDENTIAL_REPLAY".equals(t.getMethod())).count();

        long blockActions = actions.stream()
            .filter(a -> String.valueOf(a.getType()).contains("BLOCK")).count();
        long quarantineActions = actions.stream()
            .filter(a -> String.valueOf(a.getType()).contains("QUARANTINE")).count();

        // Distinct attacker IPs + ATT&CK-ish attack types from bounded telemetry.
        Set<String> attackerIps = new HashSet<>();
        Set<String> attackTypes = new HashSet<>();
        try {
            for (HoneypotLog l : honeypotRepo.findTop8000ByOrderByTimestampDesc()) {
                if (l.getSourceIp() != null) attackerIps.add(l.getSourceIp());
                if (l.getAttackType() != null && !l.getAttackType().isBlank()) attackTypes.add(l.getAttackType());
            }
        } catch (Exception ignored) { }

        // ---- Map each Engage activity to real evidence ----
        List<Map<String, Object>> acts = new ArrayList<>();

        // PREPARE
        acts.add(act("Prepare", "Plan", "Cyber Threat Intelligence",
            "Threat intel + attacker profiling",
            "Attacker behaviour and geolocation from the decoy fabric feed how decoys are shaped.",
            attackerIps.size(), attackerIps.size() + " attacker IPs profiled"));
        acts.add(act("Prepare", "Plan", "Persona Creation",
            "Believable decoy personas",
            "Each decoy wears a real ICS vendor/model persona so it is indistinguishable from genuine gear.",
            (int) personas, personas + " distinct decoy personas"));
        acts.add(act("Prepare", "Plan", "Application Diversity",
            "Diverse ICS protocol decoys",
            "The fabric spans multiple industrial protocols, matching the estate it protects.",
            (int) distinctProtocols, distinctProtocols + " protocols covered"));

        // EXPOSE
        acts.add(act("Expose", "Collect", "Network Monitoring",
            "Honeypot telemetry ingestion",
            "Every packet against the decoys is captured, decoded and stored.",
            (int) Math.min(events, Integer.MAX_VALUE), events + " decoy events collected"));
        acts.add(act("Expose", "Collect", "System Activity Monitoring",
            "Engagement + payload capture",
            "Per-attacker engagements with deep payload inspection down to the register/DB level.",
            attackerIps.size(), attackerIps.size() + " engaged sources"));
        acts.add(act("Expose", "Detect", "Lures",
            "Planted beacons (honeytokens)",
            "Decoy bookmarks and documents planted in the real environment beacon home when opened.",
            (int) beaconTokens, beaconTokens + " lures planted, " + beaconTrips + " tripped"));
        acts.add(act("Expose", "Detect", "Decoy System",
            "Running decoy fleet",
            "Internal tripwire HMIs and internet-exposed ICS decoys draw and detect intruders.",
            decoysRunning, decoysRunning + " decoys running"));

        // ELICIT
        acts.add(act("Elicit", "Motivation", "Decoy Credentials",
            "Planted credentials & API keys",
            "Fake logins/keys seeded into the estate; a replay against the fabric is a breach signal.",
            (int) credentialTokens, credentialTokens + " credential lures, " + replayTrips + " replayed"));
        acts.add(act("Elicit", "Motivation", "Decoy Content",
            "Decoy data & register values",
            "Believable process values and fake connection strings keep an intruder engaged.",
            (int) (contentTokens + decoysRunning), contentTokens + " decoy data lures + live register content"));
        acts.add(act("Elicit", "Motivation", "Decoy Network",
            "Two-tier decoy topology",
            "A layered deception network: internal tripwire subnet plus an internet-exposed decoy tier.",
            internalDecoys + externalDecoys,
            internalDecoys + " internal + " + externalDecoys + " internet-exposed decoys"));

        // AFFECT
        acts.add(act("Affect", "Disruption", "Isolation",
            "Quarantine response",
            "Quarantine a live attacker session from the response bar.",
            (int) quarantineActions, quarantineActions + " quarantine actions"));
        acts.add(act("Affect", "Prevention", "Security Controls",
            "Block response",
            "Block an attacker IP across the fabric from one place.",
            (int) blockActions, blockActions + " block actions"));

        // UNDERSTAND
        acts.add(act("Understand", "Analysis", "Threat Model",
            "ATT&CK for ICS mapping",
            "Observed decoy behaviour is mapped to ATT&CK for ICS techniques and grounded copilot assessments.",
            attackTypes.size(), attackTypes.size() + " technique classes observed"));
        acts.add(act("Understand", "Analysis", "After-Action Review",
            "Cases & NIS2 evidence",
            "Every high-confidence signal becomes a tracked case and NIS2 reporting evidence.",
            (int) cases, cases + " cases opened"));

        // ---- Coverage summary ----
        int total = acts.size();
        long active = acts.stream().filter(a -> "ACTIVE".equals(a.get("status"))).count();

        Map<String, Object> byGoal = new LinkedHashMap<>();
        for (String g : GOALS) {
            List<Map<String, Object>> inGoal = acts.stream()
                .filter(a -> g.equals(a.get("goal"))).toList();
            long act2 = inGoal.stream().filter(a -> "ACTIVE".equals(a.get("status"))).count();
            Map<String, Object> gm = new LinkedHashMap<>();
            gm.put("total", inGoal.size());
            gm.put("active", act2);
            byGoal.put(g, gm);
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("totalActivities", total);
        summary.put("activeActivities", active);
        summary.put("coveragePct", total == 0 ? 0 : Math.round(active * 100.0 / total));
        summary.put("byGoal", byGoal);

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("framework", "MITRE Engage");
        out.put("goals", GOALS);
        out.put("activities", acts);
        out.put("summary", summary);
        return out;
    }

    /** Build one activity entry; ACTIVE when there is real evidence behind it. */
    private static Map<String, Object> act(String goal, String approach, String activity,
                                           String feature, String description,
                                           int evidenceCount, String evidence) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("goal", goal);
        m.put("approach", approach);
        m.put("activity", activity);
        m.put("otShieldFeature", feature);
        m.put("description", description);
        m.put("status", evidenceCount > 0 ? "ACTIVE" : "AVAILABLE");
        m.put("evidenceCount", evidenceCount);
        m.put("evidence", evidence);
        return m;
    }

    // -------- small reflection-free helpers tolerant of the DTO shape --------

    private static String id(DecoyInstanceDTO d) {
        String s = d.getId();
        return s == null ? "" : s;
    }

    private static String vendor(DecoyInstanceDTO d) {
        try { return d.getVendor(); } catch (Exception e) { return null; }
    }

    private static String model(DecoyInstanceDTO d) {
        try { return d.getModel(); } catch (Exception e) { return null; }
    }

    private static String nn(String s) { return s == null ? "" : s; }

    private interface Sup<T> { T get() throws Exception; }

    private static <T> T safe(Sup<T> s, T fallback) {
        try { T v = s.get(); return v == null ? fallback : v; } catch (Exception e) { return fallback; }
    }
}
