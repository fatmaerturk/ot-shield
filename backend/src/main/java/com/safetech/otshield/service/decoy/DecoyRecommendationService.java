package com.safetech.otshield.service.decoy;

import com.safetech.otshield.dto.decoy.DecoyInstanceDTO;
import com.safetech.otshield.model.Alert;
import com.safetech.otshield.model.Asset;
import com.safetech.otshield.model.HoneypotLog;
import com.safetech.otshield.repository.AlertRepository;
import com.safetech.otshield.repository.AssetRepository;
import com.safetech.otshield.repository.HoneypotLogRepository;
import com.safetech.otshield.service.HoneypotLogService;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import java.util.*;

/**
 * Adaptive decoy recommendations - the seed of "self-configuring deception".
 *
 * Instead of a fixed decoy fleet, this derives which decoys the operator SHOULD
 * deploy from their own environment: the ICS protocols actually being probed on
 * the wire (honeypot telemetry) and the vendors of their real assets (asset
 * inventory), cross-referenced against what's already deployed. The output is a
 * ranked list of "deploy a &lt;vendor&gt; &lt;protocol&gt; decoy" suggestions, each with the
 * real evidence behind it - so the deception fabric mirrors the customer's
 * actual estate rather than a generic template.
 */
@Service
public class DecoyRecommendationService {

    private final HoneypotLogRepository honeypotRepo;
    private final AssetRepository assetRepo;
    private final DecoyService decoyService;
    private final AlertRepository alertRepo;

    public DecoyRecommendationService(HoneypotLogRepository honeypotRepo,
                                      AssetRepository assetRepo,
                                      DecoyService decoyService,
                                      AlertRepository alertRepo) {
        this.honeypotRepo = honeypotRepo;
        this.assetRepo = assetRepo;
        this.decoyService = decoyService;
        this.alertRepo = alertRepo;
    }

    /** Canonical ICS protocol → suggested decoy persona (vendor/model/port). */
    private record Persona(String protocol, String vendor, String model, int port) {}

    private static final Map<String, Persona> DEFAULT_PERSONA = Map.of(
        "MODBUS",      new Persona("MODBUS", "Schneider Electric", "Modicon M340", 502),
        "S7",          new Persona("S7", "Siemens", "S7-1500", 102),
        "ETHERNET_IP", new Persona("ETHERNET_IP", "Rockwell Automation", "ControlLogix 1756", 44818),
        "DNP3",        new Persona("DNP3", "GE Grid Solutions", "MiCOM P849", 20000),
        "IEC104",      new Persona("IEC104", "ABB", "RTU560", 2404),
        "BACNET",      new Persona("BACNET", "Honeywell", "Experion", 47808),
        "SNMP",        new Persona("SNMP", "Generic", "SNMP agent", 161),
        "FTP",         new Persona("FTP", "Generic", "FTP service", 21)
    );

    /**
     * The ICS protocol an asset speaks. Prefers the protocol observed from
     * traffic (set by passive discovery); falls back to inferring it from the
     * manufacturer for manually-entered assets.
     */
    private static String assetProto(Asset a) {
        if (a == null) return null;
        String p = a.getProtocol();
        if (p != null && !p.isBlank()) return canon(p);
        return protocolForManufacturer(a.getManufacturer());
    }

    /** Map a real asset manufacturer to the ICS protocol it typically speaks. */
    private static String protocolForManufacturer(String mfr) {
        if (mfr == null) return null;
        String m = mfr.toUpperCase();
        if (m.contains("SIEMENS")) return "S7";
        if (m.contains("SCHNEIDER") || m.contains("MODICON") || m.contains("TELEMECANIQUE")) return "MODBUS";
        if (m.contains("ROCKWELL") || m.contains("ALLEN") || m.contains("BRADLEY")) return "ETHERNET_IP";
        if (m.contains("ABB")) return "IEC104";
        if (m.contains("GE ") || m.equals("GE") || m.contains("GENERAL ELECTRIC")) return "DNP3";
        if (m.contains("HONEYWELL")) return "BACNET";
        if (m.contains("EMERSON") || m.contains("YOKOGAWA") || m.contains("WAGO") || m.contains("PHOENIX")) return "MODBUS";
        return null;
    }

    /**
     * Normalise the decoy fleet / honeypot protocol strings onto the canonical
     * keys used by DEFAULT_PERSONA (S7COMM → S7, etc.).
     */
    private static String canon(String p) {
        if (p == null) return null;
        String u = p.toUpperCase();
        switch (u) {
            case "S7COMM": return "S7";
            case "ENIP": case "ETHERNETIP": case "ETHERNET/IP": return "ETHERNET_IP";
            case "IEC-104": case "IEC 104": return "IEC104";
            default: return u;
        }
    }

    public List<Map<String, Object>> buildRecommendations() {
        // 1. Protocols actually being probed on the wire (real honeypot telemetry).
        Map<String, Integer> attackCount = new HashMap<>();
        Map<String, Set<String>> attackers = new HashMap<>();
        try {
            for (HoneypotLog l : honeypotRepo.findTop8000ByOrderByTimestampDesc()) {
                if (HoneypotLogService.isInternalNoise(l)) continue;
                String p = canon(l.getProtocol());
                if (p == null) continue;
                attackCount.merge(p, 1, Integer::sum);
                if (l.getSourceIp() != null) attackers.computeIfAbsent(p, k -> new HashSet<>()).add(l.getSourceIp());
            }
        } catch (Exception ignored) { }

        // 2. Vendors of the operator's real assets → implied protocols + a persona.
        Map<String, Integer> assetCount = new HashMap<>();
        Map<String, Persona> assetPersona = new LinkedHashMap<>();
        try {
            for (Asset a : assetRepo.findAll()) {
                String proto = assetProto(a);
                if (proto == null) continue;
                assetCount.merge(proto, 1, Integer::sum);
                // Prefer a persona that mirrors the real gear (vendor + model).
                assetPersona.putIfAbsent(proto, new Persona(proto,
                    a.getManufacturer(),
                    a.getModel() != null ? a.getModel() : DEFAULT_PERSONA.getOrDefault(proto, new Persona(proto, "Generic", "device", 0)).model(),
                    DEFAULT_PERSONA.getOrDefault(proto, new Persona(proto, "Generic", "device", 0)).port()));
            }
        } catch (Exception ignored) { }

        // 3. Protocols already covered by a deployed decoy.
        Set<String> deployed = new HashSet<>();
        try {
            for (DecoyInstanceDTO d : decoyService.listInstances()) {
                if (d.getProtocol() != null) deployed.add(canon(d.getProtocol().name()));
            }
        } catch (Exception ignored) { }

        // 4. Build one recommendation per candidate protocol (union of both signals).
        Set<String> candidates = new LinkedHashSet<>();
        candidates.addAll(attackCount.keySet());
        candidates.addAll(assetCount.keySet());

        List<Map<String, Object>> recs = new ArrayList<>();
        for (String proto : candidates) {
            int atk = attackCount.getOrDefault(proto, 0);
            int uips = attackers.getOrDefault(proto, Set.of()).size();
            int assets = assetCount.getOrDefault(proto, 0);
            boolean covered = deployed.contains(proto);

            Persona persona = assetPersona.getOrDefault(proto,
                DEFAULT_PERSONA.getOrDefault(proto, new Persona(proto, "Generic", "ICS device", 0)));

            String priority;
            if (!covered && (atk > 0 || assets > 0)) priority = "HIGH";
            else if (covered && (atk > 0 || assets > 0)) priority = "MEDIUM";
            else priority = "LOW";

            StringBuilder why = new StringBuilder();
            if (assets > 0) why.append(assets).append(assets == 1 ? " asset " : " assets ")
                .append("in your inventory speak ").append(proto).append(". ");
            if (atk > 0) why.append(proto).append(" was probed ").append(atk)
                .append(" times from ").append(uips).append(uips == 1 ? " attacker IP. " : " attacker IPs. ");
            if (!covered) why.append("No matching decoy is deployed - add a ")
                .append(persona.vendor()).append(" ").append(proto)
                .append(" decoy so it mirrors your estate and attackers can't tell it from a real device.");
            else why.append("A decoy already covers this protocol; keep it running.");

            Map<String, Object> r = new LinkedHashMap<>();
            r.put("protocol", proto);
            r.put("suggestedVendor", persona.vendor());
            r.put("suggestedModel", persona.model());
            r.put("suggestedPort", persona.port());
            r.put("priority", priority);
            r.put("alreadyDeployed", covered);
            // Only operator-deployed decoys (in the DB) can be undeployed; the
            // built-in fleet is fixed.
            r.put("undeployable", safeUserDeployed(proto));
            r.put("attackCount", atk);
            r.put("uniqueAttackers", uips);
            r.put("assetCount", assets);
            r.put("basedOn", persona.vendor().equalsIgnoreCase("Generic") ? "traffic" : "assets+traffic");
            r.put("rationale", why.toString().trim());
            recs.add(r);
        }

        // Rank: HIGH first, then by attack volume, then asset count.
        recs.sort((x, y) -> {
            int pr = rank((String) y.get("priority")) - rank((String) x.get("priority"));
            if (pr != 0) return pr;
            int av = ((Integer) y.get("attackCount")) - ((Integer) x.get("attackCount"));
            if (av != 0) return av;
            return ((Integer) y.get("assetCount")) - ((Integer) x.get("assetCount"));
        });
        return recs;
    }

    private static int rank(String p) {
        switch (p) { case "HIGH": return 3; case "MEDIUM": return 2; default: return 1; }
    }

    /** Per-segment aggregate used to plan segment-aware decoy placement. */
    private static class Seg {
        final String subnet;
        int assetCount;
        int purdueOrdinal = 99;          // lowest wins (LEVEL_0 = most critical)
        String purdueLabel = "unknown";
        final Set<String> protocols = new LinkedHashSet<>();
        final List<String> samples = new ArrayList<>();
        String exampleAssetId;
        Seg(String subnet) { this.subnet = subnet; }
    }

    /**
     * Segment-aware placement plan: group the real ICS inventory by network
     * segment (subnet) + Purdue level and rank where a decoy twin should sit.
     * A twin belongs IN the segment it protects so it catches lateral movement
     * there - so this turns "Place" from a protocol-wide suggestion into a
     * concrete, topology-aware placement list driven by the real estate.
     */
    public List<Map<String, Object>> buildSegmentPlan() {
        // Protocols actually probed on the wire, and protocols already mirrored.
        Map<String, Integer> attackCount = new HashMap<>();
        try {
            for (HoneypotLog l : honeypotRepo.findTop8000ByOrderByTimestampDesc()) {
                if (HoneypotLogService.isInternalNoise(l)) continue;
                String p = canon(l.getProtocol());
                if (p != null) attackCount.merge(p, 1, Integer::sum);
            }
        } catch (Exception ignored) { }
        Set<String> mirrored = new HashSet<>();
        try {
            for (DecoyInstanceDTO d : decoyService.listInstances())
                if (d.getProtocol() != null) mirrored.add(canon(d.getProtocol().name()));
        } catch (Exception ignored) { }

        // Group ICS assets by subnet.
        Map<String, Seg> segs = new LinkedHashMap<>();
        try {
            for (Asset a : assetRepo.findAll()) {
                String proto = assetProto(a);
                if (proto == null) continue; // only assets that speak an ICS protocol
                String subnet = subnetOf(a.getIpAddress());
                if (subnet == null) continue;
                Seg s = segs.computeIfAbsent(subnet, Seg::new);
                s.assetCount++;
                s.protocols.add(proto);
                int ord = a.getPurdueLevel() != null ? a.getPurdueLevel().ordinal() : 99;
                if (ord < s.purdueOrdinal) {
                    s.purdueOrdinal = ord;
                    s.purdueLabel = a.getPurdueLevel() != null ? a.getPurdueLevel().name() : "unknown";
                }
                if (s.samples.size() < 3) s.samples.add(a.getName() + " (" + a.getIpAddress() + ")");
                if (s.exampleAssetId == null) s.exampleAssetId = a.getId();
            }
        } catch (Exception ignored) { }

        List<Map<String, Object>> out = new ArrayList<>();
        for (Seg s : segs.values()) {
            boolean probed = s.protocols.stream().anyMatch(p -> attackCount.getOrDefault(p, 0) > 0);
            boolean protocolMirrored = s.protocols.stream().anyMatch(mirrored::contains);
            boolean critical = s.purdueOrdinal <= 1; // Level 0 (process) / 1 (basic control)

            String priority = (critical || probed) ? "HIGH" : "MEDIUM";
            String protoList = String.join(", ", s.protocols);

            String rec = "Place a decoy twin in " + s.subnet + " (" + prettyPurdue(s.purdueLabel) + "): "
                + s.assetCount + (s.assetCount == 1 ? " real " : " real ") + protoList + " asset"
                + (s.assetCount == 1 ? "" : "s") + " with no in-segment decoy. "
                + (probed ? protoList + " is targeted in the wild; a twin here catches lateral movement before the real device does."
                          : "A twin here catches lateral movement inside this segment.");

            Map<String, Object> r = new LinkedHashMap<>();
            r.put("subnet", s.subnet);
            r.put("purdueLevel", s.purdueLabel);
            r.put("purdueLabel", prettyPurdue(s.purdueLabel));
            r.put("assetCount", s.assetCount);
            r.put("protocols", new ArrayList<>(s.protocols));
            r.put("probed", probed);
            r.put("protocolMirrored", protocolMirrored);
            r.put("priority", priority);
            r.put("samples", s.samples);
            r.put("exampleAssetId", s.exampleAssetId);
            r.put("recommendation", rec);
            out.add(r);
        }

        // Rank: HIGH first, then most-critical Purdue, then most assets.
        out.sort((x, y) -> {
            int pr = rank((String) y.get("priority")) - rank((String) x.get("priority"));
            if (pr != 0) return pr;
            int px = purdueRank((String) x.get("purdueLevel")), py = purdueRank((String) y.get("purdueLevel"));
            if (px != py) return px - py; // lower ordinal (more critical) first
            return ((Integer) y.get("assetCount")) - ((Integer) x.get("assetCount"));
        });
        return out;
    }

    /** First three octets of an IPv4 as a /24, or null if not a dotted-quad. */
    private static String subnetOf(String ip) {
        if (ip == null) return null;
        String[] p = ip.split("\\.");
        if (p.length != 4) return null;
        try {
            for (String o : p) { int n = Integer.parseInt(o); if (n < 0 || n > 255) return null; }
        } catch (NumberFormatException e) { return null; }
        return p[0] + "." + p[1] + "." + p[2] + ".0/24";
    }

    private static int purdueRank(String level) {
        try { return Asset.PurdueLevel.valueOf(level).ordinal(); } catch (Exception e) { return 99; }
    }

    private static String prettyPurdue(String level) {
        if (level == null) return "Purdue unknown";
        switch (level) {
            case "LEVEL_0": return "Purdue L0 - process";
            case "LEVEL_1": return "Purdue L1 - basic control";
            case "LEVEL_2": return "Purdue L2 - supervisory";
            case "LEVEL_3": return "Purdue L3 - site";
            case "LEVEL_4": return "Purdue L4 - DMZ";
            case "LEVEL_5": return "Purdue L5 - enterprise";
            default: return "Purdue unknown";
        }
    }

    /**
     * Per-asset deception coverage - the bridge between the real inventory and the
     * decoy fabric. For each real asset it answers: is this asset's protocol
     * mirrored by a decoy, and has an attacker probing that protocol already been
     * seen on the fabric? Turns the inventory into the driver of self-configuring
     * deception rather than a generic asset list.
     */
    public List<Map<String, Object>> buildAssetCoverage() {
        // Real attack volume per protocol (from telemetry).
        Map<String, Integer> attackCount = new HashMap<>();
        Map<String, Set<String>> attackers = new HashMap<>();
        try {
            for (HoneypotLog l : honeypotRepo.findTop8000ByOrderByTimestampDesc()) {
                if (HoneypotLogService.isInternalNoise(l)) continue;
                String p = canon(l.getProtocol());
                if (p == null) continue;
                attackCount.merge(p, 1, Integer::sum);
                if (l.getSourceIp() != null) attackers.computeIfAbsent(p, k -> new HashSet<>()).add(l.getSourceIp());
            }
        } catch (Exception ignored) { }

        // Protocols already mirrored by a deployed decoy -> its name.
        Map<String, String> decoyForProtocol = new HashMap<>();
        try {
            for (DecoyInstanceDTO d : decoyService.listInstances()) {
                if (d.getProtocol() != null) decoyForProtocol.putIfAbsent(canon(d.getProtocol().name()), d.getName());
            }
        } catch (Exception ignored) { }

        List<Map<String, Object>> out = new ArrayList<>();
        try {
            for (Asset a : assetRepo.findAll()) {
                String proto = assetProto(a);
                Map<String, Object> r = new LinkedHashMap<>();
                r.put("assetId", a.getId());
                r.put("assetName", a.getName());
                r.put("manufacturer", a.getManufacturer());
                r.put("model", a.getModel());
                r.put("ipAddress", a.getIpAddress());

                if (proto == null) {
                    // IT gear / unmapped vendor - not an ICS protocol the fabric mirrors.
                    r.put("protocol", null);
                    r.put("applicable", false);
                    r.put("mirrored", false);
                    r.put("probed", false);
                    out.add(r);
                    continue;
                }

                boolean mirrored = decoyForProtocol.containsKey(proto);
                int atk = attackCount.getOrDefault(proto, 0);
                Persona persona = DEFAULT_PERSONA.getOrDefault(proto, new Persona(proto, "Generic", "ICS device", 0));

                r.put("protocol", proto);
                r.put("applicable", true);
                r.put("mirrored", mirrored);
                r.put("decoyName", mirrored ? decoyForProtocol.get(proto) : null);
                r.put("probed", atk > 0);
                r.put("attackCount", atk);
                r.put("uniqueAttackers", attackers.getOrDefault(proto, Set.of()).size());
                // Persona to deploy if not yet mirrored (mirror the real gear).
                r.put("suggestedVendor", a.getManufacturer() != null ? a.getManufacturer() : persona.vendor());
                r.put("suggestedModel", a.getModel() != null ? a.getModel() : persona.model());
                r.put("suggestedPort", persona.port());
                out.add(r);
            }
        } catch (Exception ignored) { }
        return out;
    }

    /**
     * Alerts linked to a real asset. An alert is an attack on a protocol; the
     * asset it threatens is the one that speaks that protocol (the asset the
     * decoy mirrors). Combines any alert that directly references the asset's IP
     * (DPI-derived) with the deception alerts on the asset's protocol.
     */
    public List<Alert> alertsForAsset(String assetId) {
        Asset a = assetRepo.findById(assetId).orElse(null);
        if (a == null) return List.of();

        LinkedHashMap<String, Alert> merged = new LinkedHashMap<>();
        try {
            if (a.getIpAddress() != null && !a.getIpAddress().isBlank()) {
                for (Alert al : alertRepo.findByIpAddress(a.getIpAddress().trim())) merged.putIfAbsent(al.getId(), al);
            }
        } catch (Exception ignored) { }

        List<String> variants = alertProtocolVariants(assetProto(a));
        try {
            if (!variants.isEmpty()) {
                for (Alert al : alertRepo.findByProtocolIn(variants, PageRequest.of(0, 100)))
                    merged.putIfAbsent(al.getId(), al);
            }
        } catch (Exception ignored) { }

        return new ArrayList<>(merged.values());
    }

    /** Raw alert protocol strings (uppercase) that correspond to a canonical protocol. */
    private static List<String> alertProtocolVariants(String canonProto) {
        if (canonProto == null) return List.of();
        switch (canonProto) {
            case "MODBUS":      return List.of("MODBUS");
            case "S7":          return List.of("S7COMM", "S7");
            case "ETHERNET_IP": return List.of("ENIP", "ETHERNET_IP", "ETHERNETIP");
            case "IEC104":      return List.of("IEC104", "IEC-104");
            case "BACNET":      return List.of("BACNET");
            case "DNP3":        return List.of("DNP3");
            default:            return List.of(canonProto);
        }
    }

    private boolean safeUserDeployed(String proto) {
        try {
            return decoyService.isUserDeployed(proto);
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Copilot tie-in: build a grounded question that asks the research copilot
     * whether a specific attacker's observed behaviour threatens the operator's
     * REAL assets. Combines first-party attack context (what this IP did on the
     * decoy fabric) with the matching real inventory (assets that speak the same
     * protocols), so the RAG copilot can answer against the ingested device
     * manuals / vulns with citations.
     */
    public Map<String, Object> buildThreatQuestion(String ip) {
        Set<String> protocols = new LinkedHashSet<>();
        Set<String> techniques = new LinkedHashSet<>();
        int count = 0;
        String country = null;
        try {
            for (HoneypotLog l : honeypotRepo.findTop8000ByOrderByTimestampDesc()) {
                if (!ip.equals(l.getSourceIp())) continue;
                count++;
                if (l.getProtocol() != null && !l.getProtocol().isBlank()) protocols.add(canon(l.getProtocol()));
                if (l.getAttackType() != null && !l.getAttackType().isBlank()) techniques.add(l.getAttackType());
                if (country == null && l.getCountry() != null && !l.getCountry().isBlank()) country = l.getCountry();
            }
        } catch (Exception ignored) { }

        // Real assets whose protocol matches what this attacker probed.
        List<String> matched = new ArrayList<>();
        try {
            for (Asset a : assetRepo.findAll()) {
                String ap = assetProto(a);
                if (ap != null && protocols.contains(ap)) {
                    matched.add((a.getManufacturer() == null ? "" : a.getManufacturer() + " ")
                        + (a.getModel() == null ? "device" : a.getModel())
                        + " speaking " + ap
                        + (a.getName() != null && !a.getName().isBlank() ? " (" + a.getName() + ")" : ""));
                }
            }
        } catch (Exception ignored) { }

        String protoList = protocols.isEmpty() ? "ICS" : String.join(", ", protocols);
        String techList = techniques.isEmpty() ? "reconnaissance" : String.join(", ", techniques);
        String assetLine = matched.isEmpty()
            ? "Our real OT environment contains ICS devices speaking " + protoList + "."
            : "Our real inventory contains: " + String.join("; ", matched) + ".";

        String question = "An attacker (" + ip + (country != null ? ", " + country : "")
            + ") engaged our " + protoList + " decoy with these techniques: " + techList
            + " (" + count + " interactions). " + assetLine
            + " Based on the device manuals and known vulnerabilities in the knowledge base, does this"
            + " attack pattern threaten these real assets? If so, name the specific weaknesses or CVEs it"
            + " could exploit and the mitigation we should apply. Cite the manual.";

        Map<String, Object> r = new LinkedHashMap<>();
        r.put("ip", ip);
        r.put("protocols", new ArrayList<>(protocols));
        r.put("techniques", new ArrayList<>(techniques));
        r.put("matchedAssets", matched);
        r.put("interactionCount", count);
        r.put("question", question);
        return r;
    }
}
