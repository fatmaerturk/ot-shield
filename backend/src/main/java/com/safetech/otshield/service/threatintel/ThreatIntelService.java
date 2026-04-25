package com.safetech.otshield.service.threatintel;

import com.safetech.otshield.dto.decoy.*;
import com.safetech.otshield.dto.threatintel.*;
import com.safetech.otshield.service.decoy.DecoyService;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.stream.Collectors;

/**
 * ThreatIntelService
 * --------------------------------------------------------------
 * Transforms raw decoy engagement data into attacker-centric threat
 * intelligence:
 *   - per-attacker TTP matrix (ATT&CK for ICS kill chain)
 *   - behavioral fingerprint
 *   - campaign clusters (same fingerprint + overlapping ASN/country)
 *   - IOC export (STIX-ish JSON, CSV, PLAIN)
 *   - mock SIEM/TAXII/MISP push
 *
 * This service owns no persistent state of its own; it reads from
 * DecoyService every call. For demo / MVP that's fine: the decoy layer
 * is the source of truth.
 */
@Service
public class ThreatIntelService {

    private final DecoyService decoyService;

    // Ordered ATT&CK for ICS kill chain used by the matrix.
    private static final List<TacticSpec> TACTICS = List.of(
        t("TA0108", "Initial Access", 1, List.of(
            tech("T0883", "Internet Accessible Device"),
            tech("T0886", "Remote Services"),
            tech("T0819", "Exploit Public-Facing Application")
        )),
        t("TA0104", "Execution", 2, List.of(
            tech("T0853", "Scripting"),
            tech("T0858", "Change Operating Mode")
        )),
        t("TA0110", "Persistence", 3, List.of(
            tech("T0889", "Modify Program"),
            tech("T0857", "System Firmware")
        )),
        t("TA0102", "Discovery", 4, List.of(
            tech("T0846", "Remote System Discovery"),
            tech("T0856", "Spoof Reporting Message"),
            tech("T0888", "Remote System Information Discovery")
        )),
        t("TA0109", "Lateral Movement", 5, List.of(
            tech("T0859", "Valid Accounts"),
            tech("T0843", "Program Download")
        )),
        t("TA0100", "Collection", 6, List.of(
            tech("T0801", "Monitor Process State"),
            tech("T0845", "Program Upload")
        )),
        t("TA0101", "Command and Control", 7, List.of(
            tech("T0869", "Standard Application Layer Protocol")
        )),
        t("TA0106", "Inhibit Response Function", 8, List.of(
            tech("T0878", "Alarm Suppression")
        )),
        t("TA0107", "Impair Process Control", 9, List.of(
            tech("T0855", "Unauthorized Command Message"),
            tech("T0836", "Modify Parameter"),
            tech("T0831", "Manipulation of Control")
        )),
        t("TA0105", "Impact", 10, List.of(
            tech("T0828", "Loss of Productivity and Revenue"),
            tech("T0826", "Loss of Availability"),
            tech("T0880", "Loss of Safety")
        ))
    );

    public ThreatIntelService(DecoyService decoyService) {
        this.decoyService = decoyService;
    }

    // ---------- Public API ----------

    /** Empty matrix skeleton (for UI static rendering before any attacker is selected). */
    public TtpMatrixDTO getEmptyMatrix() {
        return buildMatrix(Collections.emptyMap(), Collections.emptyMap(), Collections.emptyMap());
    }

    /** Attacker list with rolled-up intel. */
    public List<AttackerIntelSummaryDTO> listAttackers(String country, String asn, Integer minScore) {
        List<EngagementDTO> engagements = decoyService.listEngagements(null, null, 0, 10_000);

        // group engagements by ip
        Map<String, List<EngagementDTO>> byIp = engagements.stream()
            .filter(e -> e.getAttackerIp() != null)
            .collect(Collectors.groupingBy(EngagementDTO::getAttackerIp));

        List<AttackerIntelSummaryDTO> out = new ArrayList<>();
        for (Map.Entry<String, List<EngagementDTO>> entry : byIp.entrySet()) {
            AttackerProfileDTO p = decoyService.getAttacker(entry.getKey());
            if (p == null) continue;
            if (country != null && !country.equalsIgnoreCase(p.getCountry())) continue;
            if (asn != null && !asn.equalsIgnoreCase(p.getAsn())) continue;
            if (minScore != null && (p.getThreatScore() == null || p.getThreatScore() < minScore)) continue;
            out.add(toSummary(p, entry.getValue()));
        }
        // sort: score desc then lastSeen desc
        out.sort((a, b) -> {
            int s = Integer.compare(
                b.getThreatScore() == null ? 0 : b.getThreatScore(),
                a.getThreatScore() == null ? 0 : a.getThreatScore());
            if (s != 0) return s;
            Instant la = a.getLastSeen() == null ? Instant.EPOCH : a.getLastSeen();
            Instant lb = b.getLastSeen() == null ? Instant.EPOCH : b.getLastSeen();
            return lb.compareTo(la);
        });
        return out;
    }

    /** Full intel detail for a single attacker. */
    public AttackerIntelDetailDTO getAttackerDetail(String ip) {
        AttackerProfileDTO p = decoyService.getAttacker(ip);
        if (p == null) return null;

        List<EngagementDTO> engagements = decoyService.listEngagements(null, null, 0, 10_000)
            .stream()
            .filter(e -> ip.equals(e.getAttackerIp()))
            .collect(Collectors.toList());

        // Fetch full engagement with events for payload-level analysis
        List<EngagementDTO> full = engagements.stream()
            .map(e -> decoyService.getEngagement(e.getId()))
            .filter(Objects::nonNull)
            .collect(Collectors.toList());

        AttackerIntelSummaryDTO summary = toSummary(p, engagements);
        TtpMatrixDTO matrix = buildFilledMatrix(full);
        BehavioralFingerprintDTO fp = buildFingerprint(p, full);
        List<CampaignClusterDTO> campaigns = findCampaigns(p, fp);
        List<String> relatedIps = campaigns.stream()
            .flatMap(c -> c.getMemberIps().stream())
            .filter(x -> !x.equals(ip))
            .distinct()
            .collect(Collectors.toList());

        AttackerIntelDetailDTO detail = new AttackerIntelDetailDTO();
        detail.setSummary(summary);
        detail.setTtpMatrix(matrix);
        detail.setFingerprint(fp);
        detail.setEngagementIds(full.stream().map(EngagementDTO::getId).collect(Collectors.toList()));
        detail.setCampaigns(campaigns);
        detail.setRelatedIps(relatedIps);
        detail.setIocHighlights(buildIocHighlights(p, fp, full));
        return detail;
    }

    /** List of campaign clusters across all attackers. */
    public List<CampaignClusterDTO> listCampaigns() {
        List<AttackerIntelSummaryDTO> attackers = listAttackers(null, null, null);

        // Build fingerprints without recursing through getAttackerDetail
        Map<String, BehavioralFingerprintDTO> fps = new HashMap<>();
        for (AttackerIntelSummaryDTO a : attackers) {
            AttackerProfileDTO p = decoyService.getAttacker(a.getIp());
            if (p == null) continue;
            List<EngagementDTO> full = decoyService.listEngagements(null, null, 0, 10_000).stream()
                .filter(e -> a.getIp().equals(e.getAttackerIp()))
                .map(e -> decoyService.getEngagement(e.getId()))
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
            fps.put(a.getIp(), buildFingerprint(p, full));
        }

        // Cluster by fingerprint hash
        Map<String, List<String>> byHash = new LinkedHashMap<>();
        for (Map.Entry<String, BehavioralFingerprintDTO> e : fps.entrySet()) {
            byHash.computeIfAbsent(e.getValue().getHash(), k -> new ArrayList<>()).add(e.getKey());
        }

        List<CampaignClusterDTO> clusters = new ArrayList<>();
        int idx = 1;
        for (Map.Entry<String, List<String>> e : byHash.entrySet()) {
            if (e.getValue().size() < 2) continue; // clusters need >= 2 members
            BehavioralFingerprintDTO anchor = fps.get(e.getValue().get(0));
            clusters.add(buildCluster("camp-" + (idx++), e.getKey(), e.getValue(), anchor, attackers));
        }
        return clusters;
    }

    /** Export IOCs in the requested format. */
    public IocExportResultDTO export(IocExportRequest req) {
        String format = req.getFormat() == null ? "STIX" : req.getFormat().toUpperCase(Locale.ROOT);
        List<String> ips = (req.getAttackerIps() != null && !req.getAttackerIps().isEmpty())
            ? req.getAttackerIps()
            : listAttackers(null, null, null).stream().map(AttackerIntelSummaryDTO::getIp).collect(Collectors.toList());

        List<AttackerIntelDetailDTO> details = ips.stream()
            .map(this::getAttackerDetail)
            .filter(Objects::nonNull)
            .collect(Collectors.toList());

        String content;
        String filename;
        switch (format) {
            case "CSV":
                content = toCsv(details);
                filename = "otshield-intel-" + ts() + ".csv";
                break;
            case "PLAIN":
                content = toPlain(details);
                filename = "otshield-intel-" + ts() + ".txt";
                break;
            case "STIX":
            default:
                content = toStix(details);
                filename = "otshield-intel-" + ts() + ".json";
                format = "STIX";
                break;
        }

        IocExportResultDTO r = new IocExportResultDTO();
        r.setId("export-" + UUID.randomUUID().toString().substring(0, 8));
        r.setFormat(format);
        r.setGeneratedAt(Instant.now());
        r.setIocCount(details.size());
        r.setContent(content);
        r.setFilename(filename);
        return r;
    }

    /** Mock push to external intel platform. */
    public IntelPushResultDTO push(IntelPushRequest req) {
        IntelPushResultDTO r = new IntelPushResultDTO();
        r.setId("push-" + UUID.randomUUID().toString().substring(0, 8));
        r.setTarget(req.getTarget() == null ? "SIEM" : req.getTarget());
        r.setStatus("ACCEPTED");
        r.setPushedAt(Instant.now());
        int n = req.getAttackerIps() == null ? 0 : req.getAttackerIps().size();
        r.setPushedIocs(n);
        r.setExternalRef(r.getTarget().toLowerCase(Locale.ROOT) + "-event-" + (1000 + new Random().nextInt(9000)));
        r.setMessage("Pushed " + n + " IOC(s) to " + r.getTarget()
            + (req.getEndpoint() == null ? "" : " (" + req.getEndpoint() + ")"));
        return r;
    }

    // ---------- Helpers ----------

    private AttackerIntelSummaryDTO toSummary(AttackerProfileDTO p, List<EngagementDTO> engagements) {
        AttackerIntelSummaryDTO s = new AttackerIntelSummaryDTO();
        s.setIp(p.getIp());
        s.setAsn(p.getAsn());
        s.setAsnName(p.getAsnName());
        s.setCountry(p.getCountry());
        s.setCountryName(p.getCountryName());
        s.setFirstSeen(p.getFirstSeen());
        s.setLastSeen(p.getLastSeen());
        s.setEngagementCount(p.getEngagementCount());
        s.setDistinctDecoysHit(p.getDistinctDecoysHit());
        s.setThreatScore(p.getThreatScore());
        s.setTags(p.getTags() == null ? List.of() : new ArrayList<>(p.getTags()));
        s.setBlocked(p.getBlocked());
        s.setQuarantined(p.getQuarantined());

        // protocols
        Set<String> protos = engagements.stream()
            .map(e -> e.getProtocol() == null ? null : e.getProtocol().name())
            .filter(Objects::nonNull)
            .collect(Collectors.toCollection(TreeSet::new));
        s.setProtocols(new ArrayList<>(protos));

        // dominant tactic + distinct techniques across engagement-level MITRE
        Map<String, Integer> tacticCounts = new HashMap<>();
        Set<String> techs = new HashSet<>();
        for (EngagementDTO e : engagements) {
            if (e.getMitreTtps() == null) continue;
            for (MitreTtpDTO m : e.getMitreTtps()) {
                if (m.getTactic() != null) {
                    tacticCounts.merge(m.getTactic(), 1, Integer::sum);
                }
                if (m.getTechniqueId() != null) techs.add(m.getTechniqueId());
            }
        }
        s.setDominantTactic(tacticCounts.entrySet().stream()
            .max(Map.Entry.comparingByValue())
            .map(Map.Entry::getKey)
            .orElse(null));
        s.setDistinctTechniques(techs.size());

        // activity sparkline: last 12 * 2h buckets
        Instant now = Instant.now();
        int[] buckets = new int[12];
        for (EngagementDTO e : engagements) {
            Instant a = e.getLastActivityAt();
            if (a == null) continue;
            long hoursAgo = ChronoUnit.HOURS.between(a, now);
            int bucketIdx = (int) Math.min(11, Math.max(0, hoursAgo / 2));
            // bucket 0 = oldest, 11 = now
            buckets[11 - bucketIdx]++;
        }
        List<Integer> sparkline = new ArrayList<>(buckets.length);
        for (int b : buckets) sparkline.add(b);
        s.setActivitySparkline(sparkline);
        return s;
    }

    private TtpMatrixDTO buildFilledMatrix(List<EngagementDTO> engagements) {
        Map<String, Integer> hitCounts = new HashMap<>();          // techId -> hits
        Map<String, Integer> hitConfidence = new HashMap<>();      // techId -> sum of confidence
        Map<String, List<String>> evidence = new HashMap<>();      // techId -> event ids

        for (EngagementDTO e : engagements) {
            // engagement-level mitre
            if (e.getMitreTtps() != null) {
                for (MitreTtpDTO m : e.getMitreTtps()) {
                    if (m.getTechniqueId() == null) continue;
                    hitCounts.merge(m.getTechniqueId(), 1, Integer::sum);
                    hitConfidence.merge(m.getTechniqueId(),
                        m.getConfidence() == null ? 50 : m.getConfidence(), Integer::sum);
                }
            }
            // event-level mitre (richer)
            if (e.getEvents() != null) {
                for (EngagementEventDTO ev : e.getEvents()) {
                    if (ev.getMitre() == null || ev.getMitre().getTechniqueId() == null) continue;
                    String tid = ev.getMitre().getTechniqueId();
                    hitCounts.merge(tid, 1, Integer::sum);
                    hitConfidence.merge(tid,
                        ev.getMitre().getConfidence() == null ? 50 : ev.getMitre().getConfidence(),
                        Integer::sum);
                    evidence.computeIfAbsent(tid, k -> new ArrayList<>()).add(ev.getId());
                }
            }
        }

        return buildMatrix(hitCounts, hitConfidence, evidence);
    }

    private TtpMatrixDTO buildMatrix(
            Map<String, Integer> hitCounts,
            Map<String, Integer> hitConfidence,
            Map<String, List<String>> evidence) {

        TtpMatrixDTO m = new TtpMatrixDTO();
        List<TtpMatrixDTO.Tactic> tactics = new ArrayList<>();
        for (TacticSpec ts : TACTICS) {
            TtpMatrixDTO.Tactic t = new TtpMatrixDTO.Tactic();
            t.setId(ts.id);
            t.setName(ts.name);
            t.setOrder(ts.order);
            List<TtpMatrixDTO.Technique> techs = new ArrayList<>();
            for (TechniqueSpec tec : ts.techniques) {
                TtpMatrixDTO.Technique tech = new TtpMatrixDTO.Technique();
                tech.setId(tec.id);
                tech.setName(tec.name);
                int count = hitCounts.getOrDefault(tec.id, 0);
                tech.setObservationCount(count);
                int sumConf = hitConfidence.getOrDefault(tec.id, 0);
                tech.setConfidence(count == 0 ? 0 : Math.min(100, sumConf / count));
                tech.setEvidenceEventIds(evidence.getOrDefault(tec.id, List.of()));
                techs.add(tech);
            }
            t.setTechniques(techs);
            tactics.add(t);
        }
        m.setTactics(tactics);
        return m;
    }

    private BehavioralFingerprintDTO buildFingerprint(AttackerProfileDTO p, List<EngagementDTO> engagements) {
        BehavioralFingerprintDTO fp = new BehavioralFingerprintDTO();

        // Protocol mix
        Map<String, Integer> protoMix = new TreeMap<>();
        Map<String, Integer> fcMix = new TreeMap<>();
        Set<String> anomalies = new LinkedHashSet<>();
        Map<String, Integer> tacticCounts = new HashMap<>();
        long totalEvents = 0;
        long nightEvents = 0;

        for (EngagementDTO e : engagements) {
            if (e.getProtocol() != null) {
                int add = e.getEventCount() == null ? 1 : e.getEventCount().intValue();
                protoMix.merge(e.getProtocol().name(), add, Integer::sum);
            }
            if (e.getMitreTtps() != null) {
                for (MitreTtpDTO m : e.getMitreTtps()) {
                    if (m.getTactic() != null) tacticCounts.merge(m.getTactic(), 1, Integer::sum);
                }
            }
            if (e.getEvents() != null) {
                for (EngagementEventDTO ev : e.getEvents()) {
                    totalEvents++;
                    if (ev.getTs() != null) {
                        int hourUtc = ev.getTs().atZone(java.time.ZoneOffset.UTC).getHour();
                        if (hourUtc >= 21 || hourUtc < 6) nightEvents++;
                    }
                    if (ev.getPayload() != null) {
                        if (ev.getPayload().getFunctionCodeName() != null) {
                            fcMix.merge(ev.getPayload().getFunctionCodeName(), 1, Integer::sum);
                        } else if (ev.getPayload().getProtocolOp() != null) {
                            fcMix.merge(ev.getPayload().getProtocolOp(), 1, Integer::sum);
                        }
                        if (ev.getPayload().getAnomalyFlags() != null) {
                            anomalies.addAll(ev.getPayload().getAnomalyFlags());
                        }
                    }
                }
            }
        }

        // Dominant tactics top 3
        List<String> dominant = tacticCounts.entrySet().stream()
            .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
            .limit(3)
            .map(Map.Entry::getKey)
            .collect(Collectors.toList());
        fp.setDominantTactics(dominant);
        fp.setPattern(dominant.isEmpty() ? "Unclassified" : String.join(" -> ", dominant));
        fp.setProtocolMix(protoMix);
        // keep only top 6 function codes
        fp.setFunctionCodeMix(fcMix.entrySet().stream()
            .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
            .limit(6)
            .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (a, b) -> a, LinkedHashMap::new)));
        fp.setNotableAnomalies(new ArrayList<>(anomalies).stream().limit(8).collect(Collectors.toList()));

        // Repetition: if dominant proto >60% of events -> high
        int maxProto = protoMix.values().stream().mapToInt(Integer::intValue).max().orElse(0);
        int totalProto = protoMix.values().stream().mapToInt(Integer::intValue).sum();
        fp.setRepetitionScore(totalProto == 0 ? 0 : Math.min(100, (int) Math.round(100.0 * maxProto / totalProto)));
        fp.setNightRatio(totalEvents == 0 ? 0 : (int) Math.round(100.0 * nightEvents / totalEvents));
        // burstiness: more engagements clustered in short windows -> higher
        fp.setBurstiness(computeBurstiness(engagements));

        // Hash: dominant tactics + top protocol + top anomaly
        String hashSrc = String.join("|",
            String.join(",", dominant),
            protoMix.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey).orElse("none"),
            anomalies.stream().findFirst().orElse("none"));
        fp.setHash(Integer.toHexString(hashSrc.hashCode()));
        return fp;
    }

    private Integer computeBurstiness(List<EngagementDTO> engagements) {
        if (engagements.size() < 2) return 20;
        List<Instant> starts = engagements.stream()
            .map(EngagementDTO::getStartedAt)
            .filter(Objects::nonNull)
            .sorted()
            .collect(Collectors.toList());
        if (starts.size() < 2) return 20;
        long totalSpan = ChronoUnit.SECONDS.between(starts.get(0), starts.get(starts.size() - 1));
        if (totalSpan <= 0) return 100;
        long closeCount = 0;
        for (int i = 1; i < starts.size(); i++) {
            if (ChronoUnit.SECONDS.between(starts.get(i - 1), starts.get(i)) < 300) closeCount++;
        }
        return Math.min(100, (int) Math.round(100.0 * closeCount / starts.size()));
    }

    private List<CampaignClusterDTO> findCampaigns(AttackerProfileDTO p, BehavioralFingerprintDTO fp) {
        // For a single attacker, find other IPs sharing this fingerprint hash
        List<CampaignClusterDTO> all = listCampaignsInternal();
        return all.stream()
            .filter(c -> c.getMemberIps().contains(p.getIp()))
            .collect(Collectors.toList());
    }

    private List<CampaignClusterDTO> listCampaignsInternal() {
        // Duplicate of listCampaigns without recursion risk.
        return listCampaigns();
    }

    private CampaignClusterDTO buildCluster(
            String id, String hash, List<String> memberIps,
            BehavioralFingerprintDTO fp, List<AttackerIntelSummaryDTO> attackers) {
        CampaignClusterDTO c = new CampaignClusterDTO();
        c.setId(id);
        c.setFingerprintHash(hash);
        c.setMemberIps(memberIps);
        c.setMemberCount(memberIps.size());

        // Collect ASNs and country from members
        Set<String> asns = new TreeSet<>();
        Set<String> countries = new TreeSet<>();
        Set<String> decoyIds = new TreeSet<>();
        int maxScore = 0;
        for (String ip : memberIps) {
            AttackerIntelSummaryDTO a = attackers.stream().filter(x -> ip.equals(x.getIp())).findFirst().orElse(null);
            if (a == null) continue;
            if (a.getAsn() != null) asns.add(a.getAsn());
            if (a.getCountryName() != null) countries.add(a.getCountryName());
            if (a.getThreatScore() != null) maxScore = Math.max(maxScore, a.getThreatScore());
        }
        // Targeted decoys: take from engagements of first member
        AttackerIntelDetailDTO firstDetail = getAttackerDetailNoRecurse(memberIps.get(0));
        if (firstDetail != null && firstDetail.getSummary() != null) {
            List<EngagementDTO> engs = decoyService.listEngagements(null, null, 0, 500).stream()
                .filter(e -> memberIps.contains(e.getAttackerIp()))
                .collect(Collectors.toList());
            for (EngagementDTO e : engs) decoyIds.add(e.getDecoyInstanceId());
        }

        c.setSharedAsns(new ArrayList<>(asns));
        c.setTargetedDecoyIds(new ArrayList<>(decoyIds));
        c.setSeverityScore(maxScore);

        // Top techniques: compute from filled matrix of first member
        if (firstDetail != null && firstDetail.getTtpMatrix() != null) {
            List<String> topTids = new ArrayList<>();
            for (TtpMatrixDTO.Tactic t : firstDetail.getTtpMatrix().getTactics()) {
                for (TtpMatrixDTO.Technique tech : t.getTechniques()) {
                    if (tech.getObservationCount() != null && tech.getObservationCount() > 0) {
                        topTids.add(tech.getId());
                    }
                }
            }
            c.setTopTechniques(topTids.stream().limit(5).collect(Collectors.toList()));
        } else {
            c.setTopTechniques(List.of());
        }

        String name = (countries.isEmpty() ? "Multi-region" : String.join("/", countries))
            + " "
            + (fp.getProtocolMix() == null || fp.getProtocolMix().isEmpty()
                ? "mixed-protocol"
                : fp.getProtocolMix().entrySet().stream()
                    .max(Map.Entry.comparingByValue())
                    .map(Map.Entry::getKey).orElse("mixed"))
            + " campaign";
        c.setName(name);

        String summary = memberIps.size() + " attacker IPs sharing fingerprint " + hash
            + ", dominant pattern " + (fp.getPattern() == null ? "n/a" : fp.getPattern())
            + ", ASNs " + String.join(",", asns);
        c.setSummary(summary);
        return c;
    }

    // Avoid recursion in findCampaigns -> listCampaigns -> findCampaigns
    private AttackerIntelDetailDTO getAttackerDetailNoRecurse(String ip) {
        AttackerProfileDTO p = decoyService.getAttacker(ip);
        if (p == null) return null;
        List<EngagementDTO> full = decoyService.listEngagements(null, null, 0, 10_000).stream()
            .filter(e -> ip.equals(e.getAttackerIp()))
            .map(e -> decoyService.getEngagement(e.getId()))
            .filter(Objects::nonNull)
            .collect(Collectors.toList());
        AttackerIntelDetailDTO d = new AttackerIntelDetailDTO();
        d.setSummary(toSummary(p, full));
        d.setTtpMatrix(buildFilledMatrix(full));
        d.setFingerprint(buildFingerprint(p, full));
        d.setEngagementIds(full.stream().map(EngagementDTO::getId).collect(Collectors.toList()));
        d.setCampaigns(List.of());
        d.setRelatedIps(List.of());
        d.setIocHighlights(buildIocHighlights(p, d.getFingerprint(), full));
        return d;
    }

    private List<String> buildIocHighlights(AttackerProfileDTO p, BehavioralFingerprintDTO fp, List<EngagementDTO> engs) {
        List<String> out = new ArrayList<>();
        if (p.getAsnName() != null) out.add("ASN " + p.getAsn() + " (" + p.getAsnName() + ") reused");
        if (fp.getPattern() != null) out.add("Kill chain pattern: " + fp.getPattern());
        if (fp.getNightRatio() != null && fp.getNightRatio() >= 70) out.add("Predominantly nocturnal UTC activity (" + fp.getNightRatio() + "%)");
        if (fp.getRepetitionScore() != null && fp.getRepetitionScore() >= 80) out.add("Highly repetitive behavior (rep score " + fp.getRepetitionScore() + ")");
        if (fp.getNotableAnomalies() != null) {
            for (String a : fp.getNotableAnomalies()) out.add("Anomaly: " + a);
        }
        // distinct decoys
        long decoys = engs.stream().map(EngagementDTO::getDecoyInstanceId).distinct().count();
        out.add("Touched " + decoys + " distinct decoy(s)");
        return out.stream().limit(8).collect(Collectors.toList());
    }

    // ---------- Export encoders ----------

    private String toStix(List<AttackerIntelDetailDTO> details) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"type\": \"bundle\",\n");
        sb.append("  \"id\": \"bundle--").append(UUID.randomUUID()).append("\",\n");
        sb.append("  \"spec_version\": \"2.1\",\n");
        sb.append("  \"objects\": [\n");
        boolean first = true;
        for (AttackerIntelDetailDTO d : details) {
            if (d.getSummary() == null) continue;
            AttackerIntelSummaryDTO s = d.getSummary();
            if (!first) sb.append(",\n");
            first = false;
            sb.append("    {\n");
            sb.append("      \"type\": \"indicator\",\n");
            sb.append("      \"id\": \"indicator--").append(UUID.randomUUID()).append("\",\n");
            sb.append("      \"created\": \"").append(Instant.now()).append("\",\n");
            sb.append("      \"modified\": \"").append(Instant.now()).append("\",\n");
            sb.append("      \"pattern\": \"[ipv4-addr:value = '").append(esc(s.getIp())).append("']\",\n");
            sb.append("      \"pattern_type\": \"stix\",\n");
            sb.append("      \"valid_from\": \"").append(s.getFirstSeen() == null ? Instant.now() : s.getFirstSeen()).append("\",\n");
            sb.append("      \"labels\": [");
            List<String> labels = new ArrayList<>();
            if (s.getTags() != null) for (String t : s.getTags()) labels.add("\"" + esc(t.toLowerCase(Locale.ROOT)) + "\"");
            labels.add("\"malicious-activity\"");
            sb.append(String.join(",", labels));
            sb.append("],\n");
            sb.append("      \"x_ot_threat_score\": ").append(s.getThreatScore() == null ? 0 : s.getThreatScore()).append(",\n");
            sb.append("      \"x_ot_country\": \"").append(esc(s.getCountry())).append("\",\n");
            sb.append("      \"x_ot_asn\": \"").append(esc(s.getAsn())).append("\",\n");
            sb.append("      \"x_ot_dominant_tactic\": \"").append(esc(s.getDominantTactic())).append("\",\n");
            sb.append("      \"x_ot_techniques\": [");
            if (d.getTtpMatrix() != null) {
                List<String> tids = new ArrayList<>();
                for (TtpMatrixDTO.Tactic t : d.getTtpMatrix().getTactics()) {
                    for (TtpMatrixDTO.Technique tt : t.getTechniques()) {
                        if (tt.getObservationCount() != null && tt.getObservationCount() > 0) {
                            tids.add("\"" + esc(tt.getId()) + "\"");
                        }
                    }
                }
                sb.append(String.join(",", tids));
            }
            sb.append("]\n");
            sb.append("    }");
        }
        sb.append("\n  ]\n}\n");
        return sb.toString();
    }

    private String toCsv(List<AttackerIntelDetailDTO> details) {
        StringBuilder sb = new StringBuilder();
        sb.append("ip,country,asn,threatScore,dominantTactic,distinctTechniques,protocols,tags,blocked\n");
        for (AttackerIntelDetailDTO d : details) {
            if (d.getSummary() == null) continue;
            AttackerIntelSummaryDTO s = d.getSummary();
            sb.append(csv(s.getIp())).append(',');
            sb.append(csv(s.getCountry())).append(',');
            sb.append(csv(s.getAsn())).append(',');
            sb.append(s.getThreatScore() == null ? "" : s.getThreatScore()).append(',');
            sb.append(csv(s.getDominantTactic())).append(',');
            sb.append(s.getDistinctTechniques() == null ? "" : s.getDistinctTechniques()).append(',');
            sb.append(csv(String.join("|", s.getProtocols() == null ? List.of() : s.getProtocols()))).append(',');
            sb.append(csv(String.join("|", s.getTags() == null ? List.of() : s.getTags()))).append(',');
            sb.append(Boolean.TRUE.equals(s.getBlocked())).append('\n');
        }
        return sb.toString();
    }

    private String toPlain(List<AttackerIntelDetailDTO> details) {
        StringBuilder sb = new StringBuilder();
        sb.append("# OTShield IOC export ").append(Instant.now()).append('\n');
        for (AttackerIntelDetailDTO d : details) {
            if (d.getSummary() == null) continue;
            sb.append(d.getSummary().getIp()).append('\n');
        }
        return sb.toString();
    }

    private static String csv(String v) {
        if (v == null) return "";
        if (v.contains(",") || v.contains("\"")) return "\"" + v.replace("\"", "\"\"") + "\"";
        return v;
    }

    private static String esc(String v) {
        return v == null ? "" : v.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String ts() {
        return Instant.now().toString().replace(':', '-').substring(0, 19);
    }

    // ---------- Static tactic/technique tables ----------

    private static TacticSpec t(String id, String name, int order, List<TechniqueSpec> techs) {
        TacticSpec s = new TacticSpec();
        s.id = id; s.name = name; s.order = order; s.techniques = techs;
        return s;
    }

    private static TechniqueSpec tech(String id, String name) {
        TechniqueSpec s = new TechniqueSpec();
        s.id = id; s.name = name;
        return s;
    }

    private static class TacticSpec {
        String id; String name; int order; List<TechniqueSpec> techniques;
    }
    private static class TechniqueSpec {
        String id; String name;
    }
}
