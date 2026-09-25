package com.safetech.otshield.service.decoy;

import com.safetech.otshield.dto.decoy.*;
import com.safetech.otshield.dto.decoy.DecoyEnums.*;
import com.safetech.otshield.model.HoneypotLog;
import com.safetech.otshield.model.DeployedDecoy;
import com.safetech.otshield.repository.HoneypotLogRepository;
import com.safetech.otshield.repository.DeployedDecoyRepository;
import com.safetech.otshield.service.HoneypotLogService;
import jakarta.annotation.PostConstruct;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;

/**
 * In-memory backing for the Decoy Layer page.
 * Seeds five industrial decoys + ~30 engagements with deeply-parsed payloads,
 * and applies response actions to its own state so the UI can be exercised end-to-end
 * before swapping in a real Conpot/honeypot integration.
 */
@Service
public class DecoyService {

    // -------- State --------
    private final Map<String, DecoyInstanceDTO> instances = new ConcurrentHashMap<>();
    private final Map<String, EngagementDTO> engagements = new ConcurrentHashMap<>();
    private final Map<String, AttackerProfileDTO> attackers = new ConcurrentHashMap<>();
    private final List<DecoyActionResultDTO> actionLog = new ArrayList<>();
    private final AtomicLong actionSeq = new AtomicLong(1);

    /** External protocol (canonical) → decoy instance id, so honeypot rows route
     *  to the right Conpot/deployed decoy card. Seeded for the built-in decoys and
     *  extended at runtime by one-click deploy. */
    private final Map<String, String> extProtocolToDecoy = new ConcurrentHashMap<>();

    /** Marks attacker profiles / engagements sourced from real decoy telemetry
     *  (as opposed to the seeded demo data). */
    private static final String LIVE_SOURCE = "OTShield Decoy Fabric (live)";

    private final HoneypotLogRepository honeypotRepo;
    private final DeployedDecoyRepository deployedDecoyRepo;

    public DecoyService(HoneypotLogRepository honeypotRepo, DeployedDecoyRepository deployedDecoyRepo) {
        this.honeypotRepo = honeypotRepo;
        this.deployedDecoyRepo = deployedDecoyRepo;
    }

    // -------- Seed --------
    @PostConstruct
    void seed() {
        seedInstances();
        // Re-register decoys the operator deployed in a previous session so
        // one-click deploys survive a restart.
        reloadPersistedDecoys();
        // All engagement/attacker data is sourced from the live decoy fabric
        // (real honeypot telemetry) - no simulated seed data.
        injectRealEngagements();
    }

    /** Reload operator-deployed decoys from the DB and re-register them. */
    private void reloadPersistedDecoys() {
        if (deployedDecoyRepo == null) return;
        try {
            for (DeployedDecoy dd : deployedDecoyRepo.findAll()) {
                DecoyProtocol p = mapProtocol(dd.getProtocol());
                if (p == null) continue;
                // Skip protocols already covered by the built-in fleet.
                if (instances.containsKey("ext-" + p.name().toLowerCase())) continue;
                int prt = dd.getPort() > 0 ? dd.getPort() : defaultPortFor(p);
                registerDeployedDecoy(p,
                    dd.getVendor() != null ? dd.getVendor() : "OTShield",
                    dd.getModel() != null ? dd.getModel() : "internet-exposed decoy",
                    prt);
            }
        } catch (Exception ignored) { }
    }

    /** Refresh the live overlay so new real attackers appear without a restart. */
    @Scheduled(fixedDelay = 60_000L)
    public void refreshLiveEngagements() {
        try { injectRealEngagements(); } catch (Exception ignored) { }
    }

    /**
     * Rebuild all attacker engagements from real honeypot_logs telemetry - no
     * simulated data. Idempotent: the engagement/attacker maps are cleared and
     * rebuilt from the current honeypot rows each run. Only attackers that hit a
     * protocol mapping to a real decoy (Modbus/S7/DNP3/EtherNet-IP/OPC-UA) become
     * engagements; others still appear on the Attack Intelligence page. Decoy
     * instance counters are recomputed from the real engagements afterwards.
     */
    private void injectRealEngagements() {
        if (honeypotRepo == null) return;
        engagements.clear();
        attackers.clear();

        List<HoneypotLog> logs;
        try {
            // Read the full history (same source the honeypot stats use) so the
            // attacker list is consistent with totalAttacks/uniqueIPs. The old
            // top-8000 window silently dropped high-volume historical attackers
            // (e.g. an FTP botnet doing 20k+ hits) once newer traffic arrived.
            logs = honeypotRepo.findAllByOrderByTimestampDesc();
        } catch (Exception e) {
            return;
        }

        // Group by attacker IP (for profiles) and by (decoy, IP) (for engagements).
        Map<String, List<HoneypotLog>> byIp = new LinkedHashMap<>();
        Map<String, List<HoneypotLog>> byEng = new LinkedHashMap<>();
        for (HoneypotLog l : logs) {
            if (HoneypotLogService.isInternalNoise(l)) continue;
            String ip = l.getSourceIp();
            if (ip == null || ip.isBlank()) continue;
            String decoyId = resolveDecoyId(l);
            if (decoyId == null) continue; // protocol/source not modelled as a decoy card
            byIp.computeIfAbsent(ip, k -> new ArrayList<>()).add(l);
            byEng.computeIfAbsent(decoyId + "|" + ip, k -> new ArrayList<>()).add(l);
        }

        // One attacker profile per IP (aggregated across all of its engagements).
        for (Map.Entry<String, List<HoneypotLog>> en : byIp.entrySet()) {
            attackers.put(en.getKey(), buildAttacker(en.getKey(), en.getValue()));
        }

        // One engagement per (decoy, attacker) - attributed to the REAL decoy hit:
        // internal tripwire HMI for internal-decoy rows, Conpot protocol decoy for
        // external rows.
        for (Map.Entry<String, List<HoneypotLog>> en : byEng.entrySet()) {
            String key = en.getKey();
            int bar = key.indexOf('|');
            String decoyId = key.substring(0, bar);
            String ip = key.substring(bar + 1);
            DecoyInstanceDTO decoy = instances.get(decoyId);
            if (decoy == null) continue;
            List<HoneypotLog> hits = en.getValue();

            LocalDateTime first = null, last = null;
            int worst = 0;
            String country = null;
            boolean engWrite = false;
            for (HoneypotLog l : hits) {
                LocalDateTime ts = l.getTimestamp();
                if (ts != null) {
                    if (first == null || ts.isBefore(first)) first = ts;
                    if (last == null || ts.isAfter(last)) last = ts;
                }
                int rank = sevRank(l.getSeverity());
                if (rank > worst) worst = rank;
                if (country == null && l.getCountry() != null && !l.getCountry().isBlank()) country = l.getCountry();
                String at = l.getAttackType() == null ? "" : l.getAttackType().toLowerCase();
                if (at.contains("write") || at.contains("coil") || at.contains("exploit") || at.contains("force")) engWrite = true;
            }
            // Same nature-based scale as the attacker profile, evaluated against the
            // protocol of the decoy actually hit: an FTP decoy stays low-threat no
            // matter the hit count, while a Modbus/S7 write attempt scores high. This
            // is what the decoy card's threat (max over its engagements) reflects.
            int engCrit = icsCriticality(decoy.getProtocol() == null ? null : decoy.getProtocol().name());
            int threat = Math.min(100, engCrit
                    + ((engWrite && engCrit > 0) ? 30 : 0)
                    + Math.min(12, worst * 3)
                    + (int) Math.min(10, Math.round(Math.log10(hits.size() + 1) * 3.5)));
            boolean active = last != null && ChronoUnit.MINUTES.between(last, LocalDateTime.now()) < 10;

            EngagementDTO e = new EngagementDTO();
            e.setId("live-" + decoyId + "-" + ip);
            e.setDecoyInstanceId(decoy.getId());
            e.setDecoyName(decoy.getName());
            e.setProtocol(decoy.getProtocol());
            e.setAttackerIp(ip);
            e.setAttackerCountry(country);
            e.setStartedAt(toInstant(first));
            e.setLastActivityAt(toInstant(last));
            e.setEndedAt(active ? null : toInstant(last));
            e.setStatus(active ? EngagementStatus.ACTIVE : EngagementStatus.CLOSED);
            e.setSeverity(sevEnum(worst));
            e.setThreatScore(threat);
            e.setEventCount((long) hits.size());
            e.setMitreTtps(realMitre(hits));
            e.setEvents(buildRealEvents(e.getId(), hits));
            e.setAttackerProfile(attackers.get(ip));
            engagements.put(e.getId(), e);
        }

        // distinctDecoysHit / engagementCount per attacker
        Map<String, Set<String>> hitMap = new HashMap<>();
        for (EngagementDTO e : engagements.values()) {
            hitMap.computeIfAbsent(e.getAttackerIp(), k -> new HashSet<>()).add(e.getDecoyInstanceId());
        }
        hitMap.forEach((ip, set) -> {
            AttackerProfileDTO ap = attackers.get(ip);
            if (ap != null) {
                ap.setDistinctDecoysHit((long) set.size());
                ap.setEngagementCount((long) set.size());
            }
        });

        recomputeInstanceStats();
    }

    /** Recompute decoy instance counters (engagements, active, last-seen, threat)
     *  from the real engagements currently mapped to each instance. */
    private void recomputeInstanceStats() {
        Map<String, List<EngagementDTO>> byDecoy = new HashMap<>();
        for (EngagementDTO e : engagements.values()) {
            byDecoy.computeIfAbsent(e.getDecoyInstanceId(), k -> new ArrayList<>()).add(e);
        }
        for (DecoyInstanceDTO d : instances.values()) {
            List<EngagementDTO> es = byDecoy.getOrDefault(d.getId(), Collections.emptyList());
            d.setTotalEngagements((long) es.size());
            d.setActiveEngagements(es.stream().filter(e -> e.getStatus() == EngagementStatus.ACTIVE).count());
            d.setLastEngagementAt(es.stream().map(EngagementDTO::getLastActivityAt)
                .filter(Objects::nonNull).max(Instant::compareTo).orElse(null));
            d.setThreatScore(es.stream().mapToInt(EngagementDTO::getThreatScore).max().orElse(0));
        }
    }

    private static DecoyProtocol mapProtocol(String p) {
        if (p == null) return null;
        switch (p.toUpperCase()) {
            case "MODBUS": return DecoyProtocol.MODBUS;
            case "S7": case "S7COMM": return DecoyProtocol.S7;
            case "DNP3": return DecoyProtocol.DNP3;
            case "ETHERNETIP": case "ENIP": case "ETHERNET/IP": case "ETHERNET_IP": return DecoyProtocol.ETHERNET_IP;
            case "OPCUA": case "OPC-UA": case "OPC_UA": return DecoyProtocol.OPC_UA;
            case "IEC104": case "IEC-104": case "IEC 104": return DecoyProtocol.IEC104;
            case "BACNET": return DecoyProtocol.BACNET;
            case "SNMP": return DecoyProtocol.SNMP;
            case "FTP": return DecoyProtocol.FTP;
            case "HTTP": case "HTTPS": return DecoyProtocol.HTTP;
            default: return null;
        }
    }

    /** Resolve which decoy instance a honeypot row belongs to. Internal-decoy
     *  (tripwire) rows map to the internal HMI by site tag; external rows map to
     *  the Conpot protocol decoy. Returns null for rows we don't model as a card. */
    private String resolveDecoyId(HoneypotLog l) {
        if ("internal-decoy".equalsIgnoreCase(l.getDecoySource())) {
            String site = l.getSiteTag() == null ? "" : l.getSiteTag().toUpperCase();
            if (site.contains("SUBSTATION")) return "int-substation";
            if (site.contains("WATER")) return "int-water";
            if (site.contains("REFINERY") || site.contains("PIPELINE")) return "int-refinery";
            if (site.contains("MANUFACT") || site.contains("ASSEMBLY")) return "int-manufacturing";
            DecoyProtocol p = mapProtocol(l.getProtocol());
            if (p == DecoyProtocol.ETHERNET_IP) return "int-manufacturing";
            if (p == DecoyProtocol.IEC104) return "int-refinery";
            return "int-substation"; // default internal (Modbus)
        }
        // External - route by protocol to the registered decoy (built-in or
        // one-click-deployed via extProtocolToDecoy). Unregistered protocols
        // (nothing deployed for them yet) return null and don't form engagements.
        DecoyProtocol p = mapProtocol(l.getProtocol());
        if (p == null) return null;
        return extProtocolToDecoy.get(p.name());
    }

    /**
     * One-click deploy: register a new internet-exposed decoy for the given
     * protocol/persona and route that protocol's real honeypot traffic to it, so
     * the card immediately fills with the attackers already observed on that
     * protocol. Idempotent - returns the existing decoy if one already covers it.
     */
    public DecoyInstanceDTO deployDecoy(String protocol, String vendor, String model, Integer port) {
        DecoyProtocol p = mapProtocol(protocol);
        if (p == null) throw new IllegalArgumentException("Unsupported protocol: " + protocol);

        String existing = extProtocolToDecoy.get(p.name());
        if (existing != null && instances.containsKey(existing)) {
            return instances.get(existing);
        }

        int prt = (port != null && port > 0) ? port : defaultPortFor(p);
        String v = (vendor != null && !vendor.isBlank()) ? vendor : "OTShield";
        String m = (model != null && !model.isBlank()) ? model : "internet-exposed decoy";

        DecoyInstanceDTO d = registerDeployedDecoy(p, v, m, prt);

        // Persist so the deployed decoy survives a restart.
        try {
            if (deployedDecoyRepo != null) {
                deployedDecoyRepo.save(DeployedDecoy.builder()
                    .protocol(p.name()).vendor(v).model(m).port(prt).build());
            }
        } catch (Exception ignored) { }

        injectRealEngagements(); // immediately attribute existing traffic to the new decoy
        return instances.getOrDefault(d.getId(), d);
    }

    /** Register a deployed decoy instance in the in-memory fleet + routing map. */
    private DecoyInstanceDTO registerDeployedDecoy(DecoyProtocol p, String vendor, String model, int port) {
        String id = "ext-" + p.name().toLowerCase();
        DecoyInstanceDTO d = instance(
            id, "Internet-exposed · " + p.name(), p,
            vendor, model, "1.0", "34.122.225.46", port, purdueLevelFor(p), DecoyStatus.RUNNING,
            0, 0, 0, "Internet-exposed " + p.name() + " decoy (deployed)",
            "Internet-exposed decoy", 0.5, 0.5);
        instances.put(id, d);
        extProtocolToDecoy.put(p.name(), id);
        return d;
    }

    /**
     * Undeploy a previously one-click-deployed decoy: remove it from the fleet,
     * stop routing its protocol's traffic, drop it from the DB, and refresh
     * engagements. Only user-deployed decoys (present in deployed_decoy) can be
     * undeployed; the built-in fleet is untouched. Returns true if one was removed.
     */
    public boolean undeployDecoy(String protocol) {
        DecoyProtocol p = mapProtocol(protocol);
        if (p == null) return false;
        if (deployedDecoyRepo == null || !deployedDecoyRepo.existsById(p.name())) return false;

        instances.remove("ext-" + p.name().toLowerCase());
        extProtocolToDecoy.remove(p.name());
        try {
            deployedDecoyRepo.deleteById(p.name());
        } catch (Exception ignored) { }
        injectRealEngagements(); // its engagements fall away (protocol no longer routed)
        return true;
    }

    /** True if a decoy for this protocol was deployed by the operator (undeployable). */
    public boolean isUserDeployed(String protocol) {
        DecoyProtocol p = mapProtocol(protocol);
        return p != null && deployedDecoyRepo != null && deployedDecoyRepo.existsById(p.name());
    }

    private static int purdueLevelFor(DecoyProtocol p) {
        switch (p) {
            case MODBUS: case S7: case DNP3: case ETHERNET_IP: case IEC104: return 1;
            case BACNET: case SNMP: case OPC_UA: return 2;
            default: return 4;
        }
    }

    private static int defaultPortFor(DecoyProtocol p) {
        switch (p) {
            case MODBUS: return 502;
            case S7: return 102;
            case DNP3: return 20000;
            case ETHERNET_IP: return 44818;
            case IEC104: return 2404;
            case BACNET: return 47808;
            case SNMP: return 161;
            case FTP: return 21;
            case OPC_UA: return 4840;
            case HTTP: return 80;
            default: return 0;
        }
    }

    // OT-threat weight of a single protocol, by how directly abusing it endangers a
    // physical process. Field controllers that take writes rank highest; building
    // automation lower; plain IT services (FTP/HTTP/SSH/SNMP/Telnet) carry no OT
    // weight on their own. Returns 0 for anything not modelled as an ICS protocol.
    private int icsCriticality(String p) {
        if (p == null) return 0;
        String u = p.toUpperCase();
        if (u.contains("S7") || u.contains("MODBUS")) return 40;          // write-capable field controllers
        if (u.contains("IEC") || u.contains("DNP3")) return 35;           // telecontrol / RTU
        if (u.contains("PROFINET") || u.contains("ENIP") || u.contains("CIP")) return 30;
        if (u.contains("OPC")) return 25;
        if (u.contains("BACNET")) return 18;                              // building automation
        return 0;
    }

    private AttackerProfileDTO buildAttacker(String ip, List<HoneypotLog> hits) {
        LocalDateTime first = null, last = null;
        int worst = 0;
        String country = null;
        java.util.Set<String> protos = new java.util.HashSet<>();
        boolean writeAttempt = false;
        for (HoneypotLog l : hits) {
            LocalDateTime ts = l.getTimestamp();
            if (ts != null) {
                if (first == null || ts.isBefore(first)) first = ts;
                if (last == null || ts.isAfter(last)) last = ts;
            }
            int rank = sevRank(l.getSeverity());
            if (rank > worst) worst = rank;
            if (country == null && l.getCountry() != null && !l.getCountry().isBlank()) country = l.getCountry();
            String p = l.getProtocol() == null ? "" : l.getProtocol().toUpperCase();
            if (!p.isBlank()) protos.add(p);
            String at = l.getAttackType() == null ? "" : l.getAttackType().toLowerCase();
            if (at.contains("write") || at.contains("coil") || at.contains("exploit") || at.contains("force")) {
                writeAttempt = true;
            }
        }
        // Score by ATTACK NATURE, not volume, so three tiers separate cleanly:
        //   service noise (FTP/SSH/HTTP brute, no ICS)         -> ~10-25
        //   ICS reconnaissance (reads/scans one protocol)      -> ~30-55
        //   targeted OT actor (writes, or several ICS protos)  -> ~80-100
        // The single most critical ICS protocol touched sets the floor; a write or
        // exploit attempt against a real ICS decoy, and hitting several ICS protocols,
        // are what push a source into the top tier. Volume is a weak, capped signal so
        // a loud botnet cannot buy its way up.
        int crit       = protos.stream().mapToInt(this::icsCriticality).max().orElse(0);
        long icsProtos = protos.stream().filter(pp -> icsCriticality(pp) > 0).count();
        int writePts   = (writeAttempt && crit > 0) ? 30 : 0;
        int breadthPts = (int) Math.min(20, Math.max(0, icsProtos - 1) * 10);
        int sevPts     = Math.min(12, worst * 3);
        int volPts     = (int) Math.min(10, Math.round(Math.log10(hits.size() + 1) * 3.5));
        int threat = Math.min(100, crit + writePts + breadthPts + sevPts + volPts);
        AttackerProfileDTO ap = new AttackerProfileDTO();
        ap.setIp(ip);
        ap.setCountry(country);
        ap.setCountryName(country);
        ap.setFirstSeen(toInstant(first));
        ap.setLastSeen(toInstant(last));
        ap.setEngagementCount(1L);
        ap.setDistinctDecoysHit(1L);
        ap.setThreatScore(threat);
        List<String> tags = new ArrayList<>(List.of("LIVE"));
        tags.add(crit > 0 ? (writeAttempt ? "ICS_MANIPULATION" : "ICS_SCANNER") : "SERVICE_PROBE");
        if (icsProtos >= 2) tags.add("MULTI_PROTOCOL");
        if (hits.size() >= 1000) tags.add("HIGH_VOLUME");
        ap.setTags(tags);
        ap.setThreatIntelSource(LIVE_SOURCE);
        ap.setBlocked(false);
        ap.setQuarantined(false);
        return ap;
    }

    /** Build the engagement's event timeline from the real honeypot rows - real
     *  timestamp / protocol op / severity, no fabricated deep-payload register
     *  dumps (Conpot doesn't capture those). Capped so a noisy attacker doesn't
     *  produce thousands of events. */
    private List<EngagementEventDTO> buildRealEvents(String engId, List<HoneypotLog> hits) {
        List<HoneypotLog> sorted = new ArrayList<>(hits);
        sorted.sort(Comparator.comparing(
            (HoneypotLog l) -> l.getTimestamp() == null ? LocalDateTime.MIN : l.getTimestamp()));
        List<EngagementEventDTO> events = new ArrayList<>();
        int cap = Math.min(sorted.size(), 50);
        for (int i = 0; i < cap; i++) {
            HoneypotLog l = sorted.get(i);
            EngagementEventDTO ev = new EngagementEventDTO();
            ev.setId(UUID.randomUUID().toString());
            ev.setEngagementId(engId);
            ev.setTs(toInstant(l.getTimestamp()));
            ev.setDirection(EventDirection.INBOUND);
            ev.setSeverity(sevEnum(sevRank(l.getSeverity())));
            String op = l.getAttackType() != null ? l.getAttackType() : "Interaction";
            ev.setSummary(op + (l.getDestinationPort() != null ? " :" + l.getDestinationPort() : ""));
            PayloadDeepDTO pd = new PayloadDeepDTO();
            pd.setProtocolOp(op);
            pd.setRawAscii(l.getDescription());
            ev.setPayload(pd);
            events.add(ev);
        }
        return events;
    }

    private static Instant toInstant(LocalDateTime ldt) {
        return ldt == null ? null : ldt.atZone(ZoneId.systemDefault()).toInstant();
    }

    private static int sevRank(String s) {
        if (s == null) return 1;
        switch (s.toUpperCase()) {
            case "CRITICAL": case "HIGH": return 3;
            case "MEDIUM": return 2;
            default: return 1;
        }
    }

    private static Severity sevEnum(int rank) {
        switch (rank) {
            case 3:  return Severity.HIGH;
            case 2:  return Severity.MEDIUM;
            default: return Severity.LOW;
        }
    }

    /**
     * Map an attacker's real behaviour (protocols + attack types across their
     * hits) onto MITRE ATT&amp;CK for ICS techniques. Uses the exact technique IDs
     * in ThreatIntelService's tactic matrix so the per-attacker kill-chain
     * populates from ground truth instead of a single placeholder technique.
     */
    private List<MitreTtpDTO> realMitre(List<HoneypotLog> hits) {
        Map<String, MitreTtpDTO> t = new LinkedHashMap<>();
        boolean internal = hits.stream().anyMatch(l -> "internal-decoy".equalsIgnoreCase(l.getDecoySource()));

        // Base: any interaction is at minimum reconnaissance of the device.
        addTtp(t, "Discovery", "T0846", "Remote System Discovery", 85);
        if (internal) {
            // Inside the OT network → lateral-movement indicators.
            addTtp(t, "Initial Access", "T0886", "Remote Services", 85);
            addTtp(t, "Lateral Movement", "T0859", "Valid Accounts", 80);
        } else {
            addTtp(t, "Initial Access", "T0883", "Internet Accessible Device", 90);
        }

        boolean login = false, write = false, read = false, http = false, ftp = false,
                infoDisc = false, changeMode = false;
        for (HoneypotLog l : hits) {
            String at = l.getAttackType() == null ? "" : l.getAttackType().toLowerCase();
            String pr = l.getProtocol() == null ? "" : l.getProtocol().toUpperCase();
            if (at.contains("login") || at.contains("brute") || at.contains("credential") || at.contains("password")) login = true;
            if (at.contains("write")) write = true;
            if (at.contains("read") || at.contains("request") || at.contains("register")) read = true;
            if (at.contains("change operating") || at.contains("diagnostic")) changeMode = true;
            if (pr.equals("HTTP")) http = true;
            if (pr.equals("FTP")) ftp = true;
            if (pr.equals("SNMP") || pr.equals("BACNET") || at.contains("scan") || at.contains("recon")
                || at.contains("coils") || at.contains("discrete")) infoDisc = true;
        }

        if (login || ftp) {
            addTtp(t, "Initial Access", "T0886", "Remote Services", 80);
            addTtp(t, "Lateral Movement", "T0859", "Valid Accounts", 80);
        }
        if (http && login) addTtp(t, "Initial Access", "T0819", "Exploit Public-Facing Application", 70);
        if (read) {
            addTtp(t, "Collection", "T0801", "Monitor Process State", 75);
            addTtp(t, "Command and Control", "T0869", "Standard Application Layer Protocol", 70);
        }
        if (write) {
            addTtp(t, "Impair Process Control", "T0836", "Modify Parameter", 85);
            addTtp(t, "Impair Process Control", "T0855", "Unauthorized Command Message", 80);
            addTtp(t, "Impair Process Control", "T0831", "Manipulation of Control", 75);
        }
        if (changeMode) addTtp(t, "Execution", "T0858", "Change Operating Mode", 75);
        if (infoDisc) addTtp(t, "Discovery", "T0888", "Remote System Information Discovery", 75);

        return new ArrayList<>(t.values());
    }

    private void addTtp(Map<String, MitreTtpDTO> t, String tactic, String id, String name, int conf) {
        t.putIfAbsent(id, ttp(tactic, id, name, conf));
    }

    private void seedInstances() {
        instances.clear();

        // ── Layer 1: internal tripwire HMIs (DETECTION) - mirror decoys/docker-compose.yml.
        //    Fed by honeypot rows tagged decoySource="internal-decoy".
        instances.put("int-substation", instance(
                "int-substation", "Substation tripwire HMI", DecoyProtocol.MODBUS,
                "Siemens", "SIPROTEC (decoy)", "tripwire",
                "172.30.50.10", 502, 1, DecoyStatus.RUNNING,
                0, 0, 0, "Internal Modbus tripwire - 33 kV substation HMI",
                "Substation (internal)", 0.5, 0.55));
        instances.put("int-water", instance(
                "int-water", "Water treatment tripwire HMI", DecoyProtocol.MODBUS,
                "Schneider Electric", "Modicon (decoy)", "tripwire",
                "172.30.50.11", 502, 1, DecoyStatus.RUNNING,
                0, 0, 0, "Internal Modbus tripwire - drinking-water plant HMI",
                "Water Treatment (internal)", 0.5, 0.55));
        instances.put("int-refinery", instance(
                "int-refinery", "Refinery tripwire HMI", DecoyProtocol.IEC104,
                "ABB", "RTU560 (decoy)", "tripwire",
                "172.30.50.12", 2404, 1, DecoyStatus.RUNNING,
                0, 0, 0, "Internal IEC-104 tripwire - pipeline HMI",
                "Refinery (internal)", 0.5, 0.55));
        instances.put("int-manufacturing", instance(
                "int-manufacturing", "Manufacturing tripwire HMI", DecoyProtocol.ETHERNET_IP,
                "Rockwell Automation", "ControlLogix (decoy)", "tripwire",
                "172.30.50.13", 44818, 1, DecoyStatus.RUNNING,
                0, 0, 0, "Internal EtherNet/IP tripwire - assembly line HMI",
                "Manufacturing (internal)", 0.5, 0.55));

        // ── Layer 2: internet-exposed Conpot decoy (INTELLIGENCE) - one card per
        //    exposed protocol. Fed by external (non internal-decoy) honeypot rows.
        String conpotIp = "34.122.225.46"; // GCP VM public IP
        instances.put("ext-modbus", instance(
                "ext-modbus", "Internet-exposed ·Modbus", DecoyProtocol.MODBUS,
                "OTShield", "internet-exposed decoy", "1.0",
                conpotIp, 502, 1, DecoyStatus.RUNNING,
                0, 0, 0, "Internet-exposed Modbus decoy",
                "Internet-exposed decoy", 0.18, 0.55));
        instances.put("ext-s7", instance(
                "ext-s7", "Internet-exposed ·S7comm", DecoyProtocol.S7,
                "OTShield", "internet-exposed decoy", "1.0",
                conpotIp, 102, 1, DecoyStatus.RUNNING,
                0, 0, 0, "Internet-exposed S7comm decoy",
                "Internet-exposed decoy", 0.34, 0.55));
        instances.put("ext-iec104", instance(
                "ext-iec104", "Internet-exposed ·IEC-104", DecoyProtocol.IEC104,
                "OTShield", "internet-exposed decoy", "1.0",
                conpotIp, 2404, 1, DecoyStatus.RUNNING,
                0, 0, 0, "Internet-exposed IEC-104 decoy",
                "Internet-exposed decoy", 0.5, 0.55));
        instances.put("ext-bacnet", instance(
                "ext-bacnet", "Internet-exposed ·BACnet", DecoyProtocol.BACNET,
                "OTShield", "internet-exposed decoy", "1.0",
                conpotIp, 47808, 2, DecoyStatus.RUNNING,
                0, 0, 0, "Internet-exposed BACnet decoy",
                "Internet-exposed decoy", 0.66, 0.35));
        instances.put("ext-snmp", instance(
                "ext-snmp", "Internet-exposed ·SNMP", DecoyProtocol.SNMP,
                "OTShield", "internet-exposed decoy", "1.0",
                conpotIp, 161, 2, DecoyStatus.RUNNING,
                0, 0, 0, "Internet-exposed SNMP decoy",
                "Internet-exposed decoy", 0.82, 0.35));
        instances.put("ext-ftp", instance(
                "ext-ftp", "Internet-exposed ·FTP", DecoyProtocol.FTP,
                "OTShield", "internet-exposed decoy", "1.0",
                conpotIp, 21, 4, DecoyStatus.RUNNING,
                0, 0, 0, "Internet-exposed FTP decoy",
                "Internet-exposed decoy", 0.5, 0.15));

        // Route external honeypot traffic to the matching Conpot decoy by protocol.
        extProtocolToDecoy.clear();
        extProtocolToDecoy.put("MODBUS", "ext-modbus");
        extProtocolToDecoy.put("S7", "ext-s7");
        extProtocolToDecoy.put("IEC104", "ext-iec104");
        extProtocolToDecoy.put("BACNET", "ext-bacnet");
        extProtocolToDecoy.put("SNMP", "ext-snmp");
        extProtocolToDecoy.put("FTP", "ext-ftp");
    }

    private DecoyInstanceDTO instance(String id, String name, DecoyProtocol p,
                                     String vendor, String model, String fw,
                                     String ip, int port, int level, DecoyStatus status,
                                     long uptime, int total, int active, String desc,
                                     String facility, double fx, double fy) {
        DecoyInstanceDTO d = new DecoyInstanceDTO();
        d.setId(id);
        d.setName(name);
        d.setProtocol(p);
        d.setVendor(vendor);
        d.setModel(model);
        d.setFirmware(fw);
        d.setIpAddress(ip);
        d.setPort(port);
        d.setPurdueLevel(level);
        d.setStatus(status);
        d.setUptimeSeconds(uptime);
        d.setTotalEngagements((long) total);
        d.setActiveEngagements((long) active);
        // Honest defaults: no fabricated activity. Real engagement time and threat
        // are stamped in from live honeypot telemetry during injectRealEngagements;
        // a decoy nobody has hit stays at 0 (no attacks == no threat).
        d.setLastEngagementAt(null);
        d.setThreatScore(0);
        d.setDescription(desc);
        d.setFacility(facility);
        d.setFacilityX(fx);
        d.setFacilityY(fy);
        return d;
    }

    private MitreTtpDTO ttp(String tactic, String id, String name, int conf) {
        MitreTtpDTO t = new MitreTtpDTO();
        t.setTactic(tactic);
        t.setTechniqueId(id);
        t.setTechniqueName(name);
        t.setConfidence(conf);
        return t;
    }

    public List<DecoyInstanceDTO> listInstances() {
        return new ArrayList<>(instances.values());
    }

    public DecoyInstanceDTO getInstance(String id) {
        return instances.get(id);
    }

    public List<EngagementDTO> listEngagements(String status, String decoyId, int page, int size) {
        return engagements.values().stream()
                .filter(e -> status == null || e.getStatus().name().equalsIgnoreCase(status))
                .filter(e -> decoyId == null || decoyId.equals(e.getDecoyInstanceId()))
                .sorted(Comparator.comparing(EngagementDTO::getLastActivityAt).reversed())
                .skip((long) page * size)
                .limit(size)
                .map(this::stripDetails)
                .collect(Collectors.toList());
    }

    // Returns an engagement summary without the deep per-event payloads, for list views.
    private EngagementDTO stripDetails(EngagementDTO src) {
        EngagementDTO copy = new EngagementDTO();
        copy.setId(src.getId());
        copy.setDecoyInstanceId(src.getDecoyInstanceId());
        copy.setDecoyName(src.getDecoyName());
        copy.setProtocol(src.getProtocol());
        copy.setAttackerIp(src.getAttackerIp());
        copy.setAttackerCountry(src.getAttackerCountry());
        copy.setAttackerAsn(src.getAttackerAsn());
        copy.setStartedAt(src.getStartedAt());
        copy.setLastActivityAt(src.getLastActivityAt());
        copy.setEndedAt(src.getEndedAt());
        copy.setStatus(src.getStatus());
        copy.setSeverity(src.getSeverity());
        copy.setThreatScore(src.getThreatScore());
        copy.setEventCount(src.getEventCount());
        copy.setMitreTtps(src.getMitreTtps());
        return copy;
    }

    public EngagementDTO getEngagement(String id) {
        return engagements.get(id);
    }

    public AttackerProfileDTO getAttacker(String ip) {
        return attackers.get(ip);
    }

    public DecoyStatsDTO computeStats() {
        DecoyStatsDTO s = new DecoyStatsDTO();
        Instant cutoff = Instant.now().minus(24, ChronoUnit.HOURS);
        long active = engagements.values().stream().filter(e -> e.getStatus() == EngagementStatus.ACTIVE).count();
        long last24 = engagements.values().stream().filter(e -> e.getStartedAt().isAfter(cutoff)).count();
        long uniqueAtt = engagements.values().stream()
                .filter(e -> e.getStartedAt().isAfter(cutoff))
                .map(EngagementDTO::getAttackerIp).distinct().count();
        s.setActiveEngagements(active);
        s.setEngagementsLast24h(last24);
        s.setUniqueAttackersLast24h(uniqueAtt);
        s.setDecoysRunning(instances.values().stream().filter(d -> d.getStatus() == DecoyStatus.RUNNING).count());
        s.setDecoysTotal((long) instances.size());

        Map<String, Long> byProto = engagements.values().stream()
                .collect(Collectors.groupingBy(e -> e.getProtocol().name(), Collectors.counting()));
        s.setEngagementsByProtocol(byProto);

        Map<String, Long> tactic = new HashMap<>();
        Map<String, Long> ops = new HashMap<>();
        for (EngagementDTO e : engagements.values()) {
            if (e.getMitreTtps() != null) {
                for (MitreTtpDTO t : e.getMitreTtps()) {
                    tactic.merge(t.getTactic(), 1L, Long::sum);
                }
            }
            if (e.getEvents() != null) {
                for (EngagementEventDTO ev : e.getEvents()) {
                    if (ev.getPayload() != null && ev.getPayload().getProtocolOp() != null) {
                        ops.merge(ev.getPayload().getProtocolOp(), 1L, Long::sum);
                    }
                }
            }
        }
        s.setTopMitreTactics(tactic.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(5)
                .map(en -> {
                    DecoyStatsDTO.TopMitreEntry m = new DecoyStatsDTO.TopMitreEntry();
                    m.setTactic(en.getKey());
                    m.setCount(en.getValue());
                    return m;
                }).collect(Collectors.toList()));
        s.setTopProtocolOps(ops.entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(5)
                .map(en -> {
                    DecoyStatsDTO.TopProtocolOpEntry o = new DecoyStatsDTO.TopProtocolOpEntry();
                    o.setOp(en.getKey());
                    o.setCount(en.getValue());
                    return o;
                }).collect(Collectors.toList()));
        return s;
    }

    // -------- Actions --------

    public DecoyActionResultDTO applyAction(DecoyActionRequest req, String actor) {
        DecoyActionResultDTO out = new DecoyActionResultDTO();
        out.setId("act-" + actionSeq.getAndIncrement());
        out.setType(req.getType());
        out.setAppliedAt(Instant.now());
        out.setAppliedBy(actor != null ? actor : "system");
        Map<String, Object> result = new HashMap<>();

        switch (req.getType()) {
            case BLOCK_IP: {
                AttackerProfileDTO a = attackers.get(req.getTargetIp());
                if (a == null) { out.setStatus(DecoyActionStatus.FAILED); out.setMessage("Attacker not found"); break; }
                a.setBlocked(true);
                result.put("blockedIp", a.getIp());
                result.put("blockingRuleId", "RULE-" + UUID.randomUUID().toString().substring(0, 8));
                out.setStatus(DecoyActionStatus.APPLIED);
                out.setMessage("Blocked " + a.getIp() + " at perimeter firewall");
                break;
            }
            case UNBLOCK_IP: {
                AttackerProfileDTO a = attackers.get(req.getTargetIp());
                if (a == null) { out.setStatus(DecoyActionStatus.FAILED); out.setMessage("Attacker not found"); break; }
                a.setBlocked(false);
                out.setStatus(DecoyActionStatus.APPLIED);
                out.setMessage("Unblocked " + a.getIp());
                break;
            }
            case QUARANTINE_SESSION: {
                EngagementDTO e = engagements.get(req.getEngagementId());
                if (e == null) { out.setStatus(DecoyActionStatus.FAILED); out.setMessage("Engagement not found"); break; }
                e.setStatus(EngagementStatus.CLOSED);
                e.setEndedAt(Instant.now());
                AttackerProfileDTO ap = attackers.get(e.getAttackerIp());
                if (ap != null) ap.setQuarantined(true);
                out.setStatus(DecoyActionStatus.APPLIED);
                out.setMessage("Engagement quarantined; attacker " + e.getAttackerIp() + " isolated to deception VLAN");
                break;
            }
            case ADD_HONEYTOKEN: {
                String token = (String) (req.getParams() != null ? req.getParams().get("tokenName") : null);
                result.put("tokenId", "HT-" + UUID.randomUUID().toString().substring(0, 6));
                result.put("tokenName", token != null ? token : "credential.bait." + System.currentTimeMillis());
                out.setStatus(DecoyActionStatus.APPLIED);
                out.setMessage("Honeytoken planted on decoy " + req.getDecoyInstanceId());
                break;
            }
            case ADD_BREADCRUMB: {
                String path = (String) (req.getParams() != null ? req.getParams().get("path") : "C:\\Engineering\\TIA\\Project1.ap16");
                result.put("breadcrumb", path);
                out.setStatus(DecoyActionStatus.APPLIED);
                out.setMessage("Breadcrumb staged on " + req.getDecoyInstanceId());
                break;
            }
            case ESCALATE_ALERT: {
                EngagementDTO e = engagements.get(req.getEngagementId());
                if (e == null) { out.setStatus(DecoyActionStatus.FAILED); out.setMessage("Engagement not found"); break; }
                result.put("alertId", "ALERT-" + UUID.randomUUID().toString().substring(0, 8));
                result.put("severity", "CRITICAL");
                e.setSeverity(Severity.CRITICAL);
                out.setStatus(DecoyActionStatus.APPLIED);
                out.setMessage("Escalated to SOC tier-2 with full engagement context");
                break;
            }
            case TAG_ATTACKER: {
                AttackerProfileDTO a = attackers.get(req.getTargetIp());
                if (a == null) { out.setStatus(DecoyActionStatus.FAILED); out.setMessage("Attacker not found"); break; }
                String tag = (String) (req.getParams() != null ? req.getParams().get("tag") : "MANUAL_REVIEW");
                List<String> tags = new ArrayList<>(a.getTags() != null ? a.getTags() : List.of());
                if (!tags.contains(tag)) tags.add(tag);
                a.setTags(tags);
                out.setStatus(DecoyActionStatus.APPLIED);
                out.setMessage("Tagged " + a.getIp() + " with " + tag);
                break;
            }
            case START_INSTANCE: {
                DecoyInstanceDTO d = instances.get(req.getDecoyInstanceId());
                if (d == null) { out.setStatus(DecoyActionStatus.FAILED); out.setMessage("Decoy not found"); break; }
                d.setStatus(DecoyStatus.RUNNING);
                out.setStatus(DecoyActionStatus.APPLIED);
                out.setMessage("Decoy " + d.getName() + " started");
                break;
            }
            case STOP_INSTANCE: {
                DecoyInstanceDTO d = instances.get(req.getDecoyInstanceId());
                if (d == null) { out.setStatus(DecoyActionStatus.FAILED); out.setMessage("Decoy not found"); break; }
                d.setStatus(DecoyStatus.STOPPED);
                out.setStatus(DecoyActionStatus.APPLIED);
                out.setMessage("Decoy " + d.getName() + " stopped");
                break;
            }
            default:
                out.setStatus(DecoyActionStatus.FAILED);
                out.setMessage("Unknown action");
        }

        out.setResult(result);
        actionLog.add(out);
        return out;
    }

    public List<DecoyActionResultDTO> recentActions(int limit) {
        int from = Math.max(0, actionLog.size() - limit);
        return new ArrayList<>(actionLog.subList(from, actionLog.size()));
    }
}
