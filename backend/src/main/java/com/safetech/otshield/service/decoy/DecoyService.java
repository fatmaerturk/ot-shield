package com.safetech.otshield.service.decoy;

import com.safetech.otshield.dto.decoy.*;
import com.safetech.otshield.dto.decoy.DecoyEnums.*;
import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Service;

import java.time.Instant;
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

    // -------- Seed --------
    @PostConstruct
    void seed() {
        seedInstances();
        seedEngagements();
    }

    private void seedInstances() {
        instances.clear();

        instances.put("decoy-001", instance(
                "decoy-001", "Plant-A Modbus PLC", DecoyProtocol.MODBUS,
                "Schneider Electric", "Modicon M340", "v3.10",
                "10.20.30.5", 502, 2, DecoyStatus.RUNNING,
                3 * 86400L, 47, 2,
                "Wastewater treatment pump controller (decoy persona)",
                "Plant-A", 0.30, 0.55
        ));
        instances.put("decoy-002", instance(
                "decoy-002", "Plant-A Siemens S7", DecoyProtocol.S7,
                "Siemens", "S7-1500 CPU 1516-3 PN/DP", "FW v2.9.4",
                "10.20.30.12", 102, 2, DecoyStatus.RUNNING,
                7 * 86400L, 33, 1,
                "Boiler control PLC, exposes DB1/DB2/DB10",
                "Plant-A", 0.65, 0.40
        ));
        instances.put("decoy-003", instance(
                "decoy-003", "Plant-B DNP3 RTU", DecoyProtocol.DNP3,
                "GE Grid Solutions", "MiCOM P849", "v8.21",
                "10.40.50.22", 20000, 2, DecoyStatus.DEGRADED,
                12 * 3600L, 12, 1,
                "Substation feeder protection RTU",
                "Plant-B", 0.50, 0.50
        ));
        instances.put("decoy-004", instance(
                "decoy-004", "Refinery EtherNet/IP CLX", DecoyProtocol.ETHERNET_IP,
                "Rockwell Automation", "ControlLogix 1756-L83E", "v32.011",
                "10.60.70.40", 44818, 2, DecoyStatus.RUNNING,
                21 * 86400L, 18, 0,
                "Refinery distillation column controller",
                "Refinery", 0.50, 0.50
        ));
        instances.put("decoy-005", instance(
                "decoy-005", "Pharma OPC UA Server", DecoyProtocol.OPC_UA,
                "Kepware", "KEPServerEX 6.13", "6.13.263.0",
                "10.80.90.10", 49320, 3, DecoyStatus.RUNNING,
                5 * 86400L, 9, 0,
                "Pharma batch reactor data server",
                "Pharma", 0.50, 0.45
        ));
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
        d.setLastEngagementAt(Instant.now().minusSeconds(60L * (5 + new Random().nextInt(45))));
        d.setThreatScore(40 + new Random().nextInt(50));
        d.setDescription(desc);
        d.setFacility(facility);
        d.setFacilityX(fx);
        d.setFacilityY(fy);
        return d;
    }

    private void seedEngagements() {
        engagements.clear();
        attackers.clear();

        String[][] attackerSeeds = {
                {"185.220.101.45", "AS208294", "Quintex GmbH", "DE", "Germany"},
                {"45.155.205.12", "AS49505", "OOO Network of data-centers Selectel", "RU", "Russia"},
                {"103.97.176.14", "AS134823", "Hangzhou Alibaba Advertising Co.", "CN", "China"},
                {"23.95.227.18", "AS36352", "ColoCrossing", "US", "United States"},
                {"194.180.49.92", "AS200651", "FlokiNET ehf", "IS", "Iceland"},
                {"5.188.62.140", "AS35017", "Swiftway Sp. z o.o.", "NL", "Netherlands"},
                {"91.240.118.172", "AS204428", "SS-Net", "BG", "Bulgaria"},
                {"209.141.40.190", "AS53667", "PONYNET", "US", "United States"},
        };

        for (String[] a : attackerSeeds) {
            AttackerProfileDTO ap = new AttackerProfileDTO();
            ap.setIp(a[0]);
            ap.setAsn(a[1]);
            ap.setAsnName(a[2]);
            ap.setCountry(a[3]);
            ap.setCountryName(a[4]);
            ap.setFirstSeen(Instant.now().minus(2 + ThreadLocalRandom.current().nextInt(20), ChronoUnit.DAYS));
            ap.setLastSeen(Instant.now().minusSeconds(30L * ThreadLocalRandom.current().nextInt(1, 240)));
            ap.setEngagementCount(0L);
            ap.setDistinctDecoysHit(0L);
            ap.setThreatScore(40 + ThreadLocalRandom.current().nextInt(60));
            ap.setTags(pickTags());
            ap.setThreatIntelSource("AlienVault OTX");
            ap.setBlocked(false);
            ap.setQuarantined(false);
            attackers.put(ap.getIp(), ap);
        }

        List<String> decoyIds = new ArrayList<>(instances.keySet());
        Random r = new Random(42);

        for (int i = 0; i < 32; i++) {
            DecoyInstanceDTO decoy = instances.get(decoyIds.get(r.nextInt(decoyIds.size())));
            String[] att = attackerSeeds[r.nextInt(attackerSeeds.length)];

            Instant started = Instant.now().minusSeconds(60L * r.nextInt(24 * 60));
            int durationMin = 2 + r.nextInt(40);
            Instant lastAct = started.plusSeconds(60L * durationMin);
            boolean active = i < 4; // first 4 are still active
            EngagementStatus status = active ? EngagementStatus.ACTIVE
                    : (r.nextInt(5) == 0 ? EngagementStatus.IDLE : EngagementStatus.CLOSED);
            Instant endedAt = active ? null : lastAct;

            EngagementDTO e = new EngagementDTO();
            e.setId(UUID.randomUUID().toString());
            e.setDecoyInstanceId(decoy.getId());
            e.setDecoyName(decoy.getName());
            e.setProtocol(decoy.getProtocol());
            e.setAttackerIp(att[0]);
            e.setAttackerAsn(att[1]);
            e.setAttackerCountry(att[3]);
            e.setStartedAt(started);
            e.setLastActivityAt(active ? Instant.now().minusSeconds(15L + r.nextInt(180)) : lastAct);
            e.setEndedAt(endedAt);
            e.setStatus(status);
            e.setSeverity(pickSeverity(r));
            e.setThreatScore(50 + r.nextInt(50));
            int eventCount = 4 + r.nextInt(20);
            e.setEventCount((long) eventCount);
            e.setMitreTtps(pickMitre(decoy.getProtocol(), r));

            // populate events (deep payload)
            List<EngagementEventDTO> events = new ArrayList<>();
            Instant cursor = started;
            for (int k = 0; k < eventCount; k++) {
                cursor = cursor.plusSeconds(5L + r.nextInt(60));
                if (cursor.isAfter(e.getLastActivityAt())) cursor = e.getLastActivityAt();
                events.add(synthEvent(e.getId(), decoy.getProtocol(), cursor, k, r));
            }
            e.setEvents(events);

            // attach attacker profile reference
            AttackerProfileDTO ap = attackers.get(att[0]);
            ap.setEngagementCount(ap.getEngagementCount() + 1);
            e.setAttackerProfile(ap);

            engagements.put(e.getId(), e);
        }

        // recompute distinctDecoysHit
        Map<String, Set<String>> attackerToDecoys = new HashMap<>();
        for (EngagementDTO e : engagements.values()) {
            attackerToDecoys.computeIfAbsent(e.getAttackerIp(), k -> new HashSet<>()).add(e.getDecoyInstanceId());
        }
        attackerToDecoys.forEach((ip, set) -> {
            AttackerProfileDTO ap = attackers.get(ip);
            if (ap != null) ap.setDistinctDecoysHit((long) set.size());
        });
    }

    private List<String> pickTags() {
        List<String> all = List.of("RECONNAISSANCE", "BRUTEFORCE", "PROTOCOL_ABUSE",
                "TOR_EXIT", "KNOWN_BOTNET", "CREDENTIAL_STUFFING", "ICS_SCANNER");
        Collections.shuffle(new ArrayList<>(all));
        int n = 1 + ThreadLocalRandom.current().nextInt(3);
        return all.subList(0, Math.min(n, all.size()));
    }

    private Severity pickSeverity(Random r) {
        int v = r.nextInt(100);
        if (v < 10) return Severity.CRITICAL;
        if (v < 35) return Severity.HIGH;
        if (v < 75) return Severity.MEDIUM;
        return Severity.LOW;
    }

    private List<MitreTtpDTO> pickMitre(DecoyProtocol p, Random r) {
        List<MitreTtpDTO> base = new ArrayList<>();
        base.add(ttp("Discovery", "T0846", "Remote System Discovery", 80 + r.nextInt(20)));
        if (r.nextBoolean())
            base.add(ttp("Discovery", "T0842", "Network Sniffing", 60 + r.nextInt(30)));
        if (p == DecoyProtocol.MODBUS || p == DecoyProtocol.S7) {
            base.add(ttp("Impair Process Control", "T0836", "Modify Parameter", 70 + r.nextInt(25)));
        }
        if (p == DecoyProtocol.DNP3 && r.nextBoolean()) {
            base.add(ttp("Inhibit Response Function", "T0816", "Device Restart/Shutdown", 75 + r.nextInt(20)));
        }
        if (p == DecoyProtocol.OPC_UA && r.nextBoolean()) {
            base.add(ttp("Collection", "T0801", "Monitor Process State", 65 + r.nextInt(25)));
        }
        return base;
    }

    private MitreTtpDTO ttp(String tactic, String id, String name, int conf) {
        MitreTtpDTO t = new MitreTtpDTO();
        t.setTactic(tactic);
        t.setTechniqueId(id);
        t.setTechniqueName(name);
        t.setConfidence(conf);
        return t;
    }

    private EngagementEventDTO synthEvent(String engId, DecoyProtocol p, Instant ts, int seq, Random r) {
        EngagementEventDTO ev = new EngagementEventDTO();
        ev.setId(UUID.randomUUID().toString());
        ev.setEngagementId(engId);
        ev.setTs(ts);
        ev.setDirection(seq % 2 == 0 ? EventDirection.INBOUND : EventDirection.OUTBOUND);
        Severity sev = (seq == 3 || seq == 7) ? Severity.HIGH : (r.nextInt(6) == 0 ? Severity.MEDIUM : Severity.LOW);
        ev.setSeverity(sev);
        ev.setPayload(synthPayload(p, seq, r));
        ev.setSummary(ev.getPayload().getProtocolOp() + (ev.getPayload().getAddressRange() != null
                ? " @ " + ev.getPayload().getAddressRange() : ""));
        if (sev != Severity.LOW) {
            ev.setMitre(ttp("Impair Process Control", "T0836", "Modify Parameter", 75));
        }
        return ev;
    }

    private PayloadDeepDTO synthPayload(DecoyProtocol p, int seq, Random r) {
        PayloadDeepDTO d = new PayloadDeepDTO();
        d.setTransactionId(1000 + seq);
        switch (p) {
            case MODBUS: {
                boolean write = (seq % 5 == 3);
                d.setProtocolOp(write ? "MODBUS.WRITE_MULTIPLE_REGISTERS" : "MODBUS.READ_HOLDING_REGISTERS");
                d.setFunctionCodeHex(write ? "0x10" : "0x03");
                d.setFunctionCodeName(write ? "Write Multiple Registers" : "Read Holding Registers");
                d.setUnitId(1);
                int start = 40001 + r.nextInt(20);
                int qty = write ? 2 : 10;
                d.setAddressRange(start + ".." + (start + qty - 1));
                d.setByteCount(qty * 2);
                StringBuilder hex = new StringBuilder();
                List<PayloadFieldDTO> fields = new ArrayList<>();
                for (int i = 0; i < qty; i++) {
                    int v = write && i == 0 ? 0xFFFF : r.nextInt(0x1000);
                    hex.append(String.format("%04X ", v));
                    PayloadFieldDTO f = new PayloadFieldDTO();
                    f.setName("HR " + (start + i));
                    f.setType("REGISTER");
                    f.setValue(String.valueOf(v));
                    f.setRawHex(String.format("0x%04X", v));
                    f.setUnit(i == 0 ? "RPM" : i == 1 ? "°C" : null);
                    if (write && i == 0) {
                        f.setFlagged(true);
                        f.setAnomalyReason("Out-of-range setpoint write to pump speed register");
                        d.setAnomalyFlags(List.of("UNAUTHORIZED_WRITE", "OUT_OF_RANGE"));
                    } else {
                        f.setFlagged(false);
                    }
                    fields.add(f);
                }
                d.setRawHex(hex.toString().trim());
                d.setRawAscii(toAscii(d.getRawHex()));
                d.setFields(fields);
                break;
            }
            case S7: {
                boolean write = (seq % 6 == 4);
                d.setProtocolOp(write ? "S7.WRITE_VAR" : "S7.READ_VAR");
                d.setFunctionCodeHex(write ? "0x05" : "0x04");
                d.setFunctionCodeName(write ? "Write Variable" : "Read Variable");
                d.setUnitId(2);
                d.setAddressRange("DB1.DBW10..DB1.DBW18");
                List<PayloadFieldDTO> fields = new ArrayList<>();
                fields.add(field("DB1.DBW10", "DB", String.valueOf(1500 + r.nextInt(50)), "0x05DC", "rpm", false, null));
                fields.add(field("DB1.DBW12", "DB", String.valueOf(72 + r.nextInt(8)),    "0x004A", "°C",  false, null));
                fields.add(field("DB1.DBW14", "DB", write ? "1" : "0", "0x0001", null, write,
                        write ? "Manual override bit set on critical interlock" : null));
                fields.add(field("DB1.DBW16", "DB", String.valueOf(r.nextInt(100)),       "0x0040", "%",   false, null));
                d.setFields(fields);
                d.setRawHex("32 01 00 00 00 00 00 0E 00 00 04 01 12 0A 10 02 00 04 00 01 84 00 00 50");
                d.setRawAscii(toAscii(d.getRawHex()));
                if (write) d.setAnomalyFlags(List.of("INTERLOCK_OVERRIDE"));
                break;
            }
            case DNP3: {
                boolean restart = (seq == 7);
                d.setProtocolOp(restart ? "DNP3.COLD_RESTART" : "DNP3.READ_CLASS_0123");
                d.setFunctionCodeHex(restart ? "0x0D" : "0x01");
                d.setFunctionCodeName(restart ? "Cold Restart" : "Read");
                d.setUnitId(10);
                d.setAddressRange(restart ? "DEVICE" : "Class 0,1,2,3 / Index 0..15");
                List<PayloadFieldDTO> fields = new ArrayList<>();
                if (restart) {
                    fields.add(field("Object 12 Var 1 Index 0", "OBJECT", "Cold Restart", "0C 01", null, true,
                            "Cold restart command issued to substation RTU"));
                    d.setAnomalyFlags(List.of("DEVICE_DISRUPTION", "OUT_OF_HOURS"));
                } else {
                    fields.add(field("Class 0 Static Data", "OBJECT", "16 points", null, null, false, null));
                    fields.add(field("Class 1 Events",      "OBJECT", "3 events",  null, null, false, null));
                    fields.add(field("Class 2 Events",      "OBJECT", "0 events",  null, null, false, null));
                }
                d.setFields(fields);
                d.setRawHex(restart ? "05 64 0B C4 0A 00 01 00 1B E2 C0 C1 0D" : "05 64 0E C4 0A 00 01 00 6F 0F C0 C1 01 3C 02 06 3C 03 06 3C 04 06");
                d.setRawAscii(toAscii(d.getRawHex()));
                break;
            }
            case ETHERNET_IP: {
                d.setProtocolOp("ENIP.SEND_RR_DATA");
                d.setFunctionCodeHex("0x6F");
                d.setFunctionCodeName("Send RR Data (CIP)");
                d.setUnitId(0);
                d.setAddressRange("Class 0x6B Instance 1");
                List<PayloadFieldDTO> fields = new ArrayList<>();
                fields.add(field("Identity Vendor ID", "ATTRIBUTE", "1 (Rockwell)", "0x0001", null, false, null));
                fields.add(field("Identity Product Code", "ATTRIBUTE", "94", "0x005E", null, false, null));
                fields.add(field("Identity Revision", "ATTRIBUTE", "32.11", null, null, false, null));
                fields.add(field("Identity Status", "ATTRIBUTE", "0x0030", "0x0030", null, false, null));
                d.setFields(fields);
                d.setRawHex("6F 00 18 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02 00 00 00 00 00 B2 00 08 00");
                d.setRawAscii(toAscii(d.getRawHex()));
                break;
            }
            case OPC_UA: {
                boolean browse = (seq % 4 == 0);
                d.setProtocolOp(browse ? "OPCUA.BROWSE" : "OPCUA.READ");
                d.setFunctionCodeName(browse ? "Browse Service" : "Read Service");
                d.setUnitId(0);
                d.setAddressRange("ns=2;s=BatchReactor.Recipe");
                List<PayloadFieldDTO> fields = new ArrayList<>();
                fields.add(field("ns=2;s=BatchReactor.Temperature", "NODE", "82.4", null, "°C", false, null));
                fields.add(field("ns=2;s=BatchReactor.Pressure",    "NODE", "1.32", null, "bar", false, null));
                fields.add(field("ns=2;s=BatchReactor.RecipeId",    "NODE", "RX-204", null, null, !browse,
                        !browse ? "Read of recipe identifier from unauthenticated session" : null));
                d.setFields(fields);
                d.setRawHex("4D 53 47 46 78 00 00 00 01 00 00 00 ...");
                d.setRawAscii("MSGF .. HEL");
                if (!browse) d.setAnomalyFlags(List.of("UNAUTHENTICATED_READ"));
                break;
            }
        }
        return d;
    }

    private PayloadFieldDTO field(String name, String type, String value, String hex, String unit,
                                  boolean flagged, String reason) {
        PayloadFieldDTO f = new PayloadFieldDTO();
        f.setName(name);
        f.setType(type);
        f.setValue(value);
        f.setRawHex(hex);
        f.setUnit(unit);
        f.setFlagged(flagged);
        f.setAnomalyReason(reason);
        return f;
    }

    private String toAscii(String hex) {
        StringBuilder sb = new StringBuilder();
        for (String b : hex.split(" ")) {
            if (b.length() < 2) continue;
            try {
                int v = Integer.parseInt(b, 16);
                sb.append(v >= 32 && v < 127 ? (char) v : '.');
            } catch (NumberFormatException ignored) {
                sb.append('.');
            }
        }
        return sb.toString();
    }

    // -------- Public API used by the controller --------

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
