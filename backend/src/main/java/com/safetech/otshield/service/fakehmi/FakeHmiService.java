package com.safetech.otshield.service.fakehmi;

import com.safetech.otshield.dto.fakehmi.*;
import com.safetech.otshield.dto.fakehmi.FakeHmiEnums.*;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;

/**
 * In-memory simulator for the Fake HMI deception feature.
 * Seeds four HMI personas (one per scenario) and drives realistic metric
 * drift / alarm toggling on a 2-second tick. Exposes a listener hook so a
 * WebSocket handler can relay envelopes to connected clients.
 *
 * Persona identity (IP / port / vendor / site_tag / HMI_TYPE) is sourced
 * from the docker-compose tripwire fleet at /decoys/docker-compose.yml so
 * that real intrusions arriving via /api/honeypot/ingest can be routed
 * back to the matching HMI card without any guesswork.
 */
@Service
public class FakeHmiService {

    // -------- State --------
    private final Map<String, FakeHmiInstanceDTO> instances = new ConcurrentHashMap<>();
    private final Map<String, List<HmiInteractionDTO>> interactionLog = new ConcurrentHashMap<>();
    private final AtomicLong seq = new AtomicLong(1);

    // -------- Lookup indices: tripwire identity -> HMI id --------
    // Populated in seedInstances(); used by recordTripwireHit() to route
    // an inbound /api/honeypot/ingest event to the right HMI instance.
    private final Map<String, String> hmiByType    = new ConcurrentHashMap<>(); // SUBSTATION/WATER_TREATMENT/REFINERY/MANUFACTURING -> hmi-id
    private final Map<String, String> hmiBySiteTag = new ConcurrentHashMap<>(); // SUBSTATION-NORTH-33KV -> hmi-id

    // -------- Listener hook for WebSocket relays --------
    public interface Listener {
        void onEnvelope(Map<String, Object> envelope);
    }
    private final List<Listener> listeners = new CopyOnWriteArrayList<>();
    public void addListener(Listener l) { listeners.add(l); }
    public void removeListener(Listener l) { listeners.remove(l); }
    private void emit(Map<String, Object> env) {
        for (Listener l : listeners) {
            try { l.onEnvelope(env); } catch (Exception ignored) {}
        }
    }

    // -------- Scheduler --------
    private ScheduledExecutorService ticker;

    @PostConstruct
    void start() {
        seedInstances();
        ticker = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "fakehmi-sim");
            t.setDaemon(true);
            return t;
        });
        ticker.scheduleAtFixedRate(this::tick, 2, 2, TimeUnit.SECONDS);
    }

    @PreDestroy
    void stop() {
        if (ticker != null) ticker.shutdownNow();
    }

    // ==================================================================
    // Public API
    // ==================================================================

    public List<FakeHmiInstanceDTO> listInstances() {
        List<FakeHmiInstanceDTO> copy = new ArrayList<>();
        for (FakeHmiInstanceDTO src : instances.values()) {
            copy.add(shallowCopyForList(src));
        }
        copy.sort(Comparator.comparing(FakeHmiInstanceDTO::getName));
        return copy;
    }

    public FakeHmiInstanceDTO getInstance(String id) {
        FakeHmiInstanceDTO src = instances.get(id);
        if (src == null) return null;
        FakeHmiInstanceDTO out = shallowCopyForList(src);
        // attach last 25 interactions on detail
        List<HmiInteractionDTO> log = interactionLog.getOrDefault(id, Collections.emptyList());
        int from = Math.max(0, log.size() - 25);
        out.setRecentInteractions(new ArrayList<>(log.subList(from, log.size())));
        return out;
    }

    public FakeHmiStatsDTO stats() {
        FakeHmiStatsDTO s = new FakeHmiStatsDTO();
        int total = instances.size();
        int running = 0;
        int alarms = 0;
        long hits24 = 0L;
        Set<String> distinctIps = new HashSet<>();
        Map<HmiScenarioType, Long> targetCount = new EnumMap<>(HmiScenarioType.class);
        Instant cutoff = Instant.now().minusSeconds(24 * 3600);

        for (FakeHmiInstanceDTO h : instances.values()) {
            if (h.getStatus() == HmiStatus.RUNNING) running++;
            for (HmiAlarmDTO a : h.getAlarms()) {
                if (Boolean.FALSE.equals(a.getAcknowledged())) alarms++;
            }
            List<HmiInteractionDTO> log = interactionLog.getOrDefault(h.getId(), Collections.emptyList());
            long cnt = 0;
            for (HmiInteractionDTO ix : log) {
                if (ix.getTs() != null && ix.getTs().isAfter(cutoff)) {
                    cnt++;
                    if (ix.getAttackerIp() != null) distinctIps.add(ix.getAttackerIp());
                }
            }
            hits24 += cnt;
            targetCount.merge(h.getScenario(), cnt, Long::sum);
        }
        s.setTotalHmis(total);
        s.setRunningHmis(running);
        s.setActiveAlarms(alarms);
        s.setInteractions24h(hits24);
        s.setDistinctAttackers24h(distinctIps.size());
        s.setMostTargetedScenario(targetCount.entrySet().stream()
                .max(Map.Entry.comparingByValue())
                .map(Map.Entry::getKey)
                .orElse(HmiScenarioType.WATER_TREATMENT));
        return s;
    }

    /** Record an attacker interaction. Appends to log and broadcasts envelope. */
    public HmiInteractionDTO recordInteraction(String hmiId, HmiInteractionRequest req, String remoteAddr) {
        FakeHmiInstanceDTO h = instances.get(hmiId);
        if (h == null) return null;
        HmiInteractionDTO ix = new HmiInteractionDTO();
        ix.setId("ix-" + seq.getAndIncrement());
        ix.setHmiId(hmiId);
        ix.setTs(Instant.now());
        String ip = (req.getAttackerIp() != null && !req.getAttackerIp().isBlank()) ? req.getAttackerIp() : remoteAddr;
        ix.setAttackerIp(ip != null ? ip : "0.0.0.0");
        ix.setAttackerCountry(guessCountryForIp(ix.getAttackerIp()));
        ix.setType(req.getType() != null ? req.getType() : HmiInteractionType.PAGE_VIEW);
        ix.setTarget(req.getTarget());
        ix.setPayload(truncate(req.getPayload(), 256));
        ix.setUserAgent(truncate(req.getUserAgent(), 128));
        ix.setBlocked(req.getType() == HmiInteractionType.CONTROL_WRITE); // we always reject writes on decoys

        interactionLog.computeIfAbsent(hmiId, k -> Collections.synchronizedList(new ArrayList<>())).add(ix);

        // bump rollups
        h.setTotalInteractions((h.getTotalInteractions() == null ? 0L : h.getTotalInteractions()) + 1);
        h.setLastAccessedAt(ix.getTs());
        recomputeThreatScore(h);

        Map<String, Object> env = new LinkedHashMap<>();
        env.put("kind", "INTERACTION");
        env.put("hmiId", hmiId);
        env.put("interaction", ix);
        emit(env);
        return ix;
    }

    /**
     * Route a real Docker tripwire hit (forwarded by tripwire_hmi.py and
     * persisted by HoneypotController.persistInternalDecoyAlarm) into the
     * matching fake HMI instance. We resolve the target HMI by HMI_TYPE
     * first, then by HMI_SITE_TAG, so events line up with the right card
     * regardless of which header the sidecar populated.
     *
     * Each tripwire hit produces:
     *   1. an INTERACTION row (CONFIG_PROBE for read-style protocols,
     *      CONTROL_WRITE for known write/command protocols) so the threat
     *      score and Recent Interactions feed both light up.
     *   2. a CRITICAL alarm on the HMI's alarm strip — a single inbound
     *      connection to a tripwire HMI is by definition lateral movement.
     *   3. WebSocket envelopes so the FakeHmisTab card flashes immediately.
     */
    public void recordTripwireHit(String hmiType,
                                  String siteTag,
                                  String vendor,
                                  String protocol,
                                  String sourceIp,
                                  Integer sourcePort,
                                  Integer destPort,
                                  String payloadSnippet) {
        // 1) Resolve target HMI
        String hmiId = null;
        if (hmiType != null && !hmiType.isBlank()) {
            hmiId = hmiByType.get(hmiType.trim().toUpperCase());
        }
        if (hmiId == null && siteTag != null && !siteTag.isBlank()) {
            hmiId = hmiBySiteTag.get(siteTag.trim());
        }
        if (hmiId == null) return; // unknown tripwire — leave the HoneypotLog row but skip routing
        FakeHmiInstanceDTO h = instances.get(hmiId);
        if (h == null) return;

        Instant now = Instant.now();
        String proto = protocol == null ? "TCP" : protocol.toUpperCase();
        String src   = (sourceIp == null || sourceIp.isBlank()) ? "0.0.0.0" : sourceIp;
        String site  = siteTag != null && !siteTag.isBlank() ? siteTag : h.getFacility();

        // 2) Append an interaction row + bump threat score
        HmiInteractionDTO ix = new HmiInteractionDTO();
        ix.setId("ix-tw-" + seq.getAndIncrement());
        ix.setHmiId(hmiId);
        ix.setTs(now);
        ix.setAttackerIp(src);
        ix.setAttackerCountry(guessCountryForIp(src));
        // Map protocol to a meaningful interaction type. Modbus / S7 / IEC104
        // requests are reads/probes; we treat any inbound connection on these
        // tripwires as CONFIG_PROBE because there is no legitimate reason to
        // touch them at all.
        ix.setType(HmiInteractionType.CONFIG_PROBE);
        ix.setTarget(proto + ":" + (destPort != null ? destPort : "?"));
        ix.setPayload(truncate(
            "tripwire " + proto + " probe from " + src + ":" + (sourcePort != null ? sourcePort : "?")
                + (payloadSnippet != null && !payloadSnippet.isBlank() ? " · payload=" + payloadSnippet : ""),
            256));
        ix.setUserAgent("internal-decoy/" + (vendor != null ? vendor : "GENERIC"));
        ix.setBlocked(true); // tripwire never relays the connection upstream

        interactionLog.computeIfAbsent(hmiId, k -> Collections.synchronizedList(new ArrayList<>())).add(ix);
        h.setTotalInteractions((h.getTotalInteractions() == null ? 0L : h.getTotalInteractions()) + 1);
        h.setLastAccessedAt(now);
        recomputeThreatScore(h);

        Map<String, Object> ixEnv = new LinkedHashMap<>();
        ixEnv.put("kind", "INTERACTION");
        ixEnv.put("hmiId", hmiId);
        ixEnv.put("interaction", ix);
        emit(ixEnv);

        // 3) Raise a CRITICAL alarm — every tripwire hit is lateral movement
        HmiAlarmDTO a = new HmiAlarmDTO();
        a.setId("alm-tw-" + seq.getAndIncrement());
        a.setTag("tripwire");
        a.setSeverity(HmiAlarmSeverity.CRITICAL);
        a.setMessage(String.format(
            "Lateral-movement probe on %s tripwire (%s) from %s:%s — site %s, dst :%s",
            proto, vendor != null ? vendor : "GENERIC",
            src, sourcePort != null ? sourcePort.toString() : "?",
            site, destPort != null ? destPort.toString() : "?"));
        a.setTs(now);
        a.setAcknowledged(false);
        a.setSource("Tripwire/Docker");

        h.getAlarms().add(0, a);
        if (h.getAlarms().size() > 20) h.getAlarms().subList(20, h.getAlarms().size()).clear();

        Map<String, Object> aEnv = new LinkedHashMap<>();
        aEnv.put("kind", "ALARM");
        aEnv.put("hmiId", hmiId);
        aEnv.put("alarm", a);
        emit(aEnv);
    }

    // ==================================================================
    // Simulation tick
    // ==================================================================

    private void tick() {
        try {
            for (FakeHmiInstanceDTO h : instances.values()) {
                if (h.getStatus() != HmiStatus.RUNNING) continue;
                driftMetrics(h);
                maybeRaiseAlarm(h);
                maybeAutoAckOldAlarms(h);
                h.setUptimeSeconds((h.getUptimeSeconds() == null ? 0L : h.getUptimeSeconds()) + 2L);
                Map<String, Object> env = new LinkedHashMap<>();
                env.put("kind", "METRIC_UPDATE");
                env.put("hmiId", h.getId());
                env.put("metrics", h.getMetrics());
                emit(env);
            }
        } catch (Exception ignored) {}
    }

    private void driftMetrics(FakeHmiInstanceDTO h) {
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        for (HmiMetricDTO m : h.getMetrics()) {
            if (m.getValue() == null) continue;
            double range = Math.max(1.0, (m.getMax() == null ? 100 : m.getMax()) - (m.getMin() == null ? 0 : m.getMin()));
            double delta = (rng.nextDouble() - 0.5) * range * 0.03;  // ~3% of range per tick
            double before = m.getValue();
            double nv = before + delta;
            // occasional excursion (3% chance) pushes metric out of band briefly
            if (rng.nextInt(100) < 3 && m.getMax() != null) {
                nv = m.getMax() + rng.nextDouble() * 0.08 * range;
            }
            m.setValue(round2(nv));
            m.setTrend(Double.compare(nv, before));
            boolean alarming = false;
            if (m.getMin() != null && nv < m.getMin()) alarming = true;
            if (m.getMax() != null && nv > m.getMax()) alarming = true;
            m.setAlarming(alarming);
        }
    }

    private void maybeRaiseAlarm(FakeHmiInstanceDTO h) {
        ThreadLocalRandom rng = ThreadLocalRandom.current();
        // 6% chance per tick per HMI to raise a new alarm from an alarming metric
        if (rng.nextInt(100) >= 6) return;
        List<HmiMetricDTO> alarming = new ArrayList<>();
        for (HmiMetricDTO m : h.getMetrics()) {
            if (Boolean.TRUE.equals(m.getAlarming())) alarming.add(m);
        }
        if (alarming.isEmpty()) return;
        HmiMetricDTO m = alarming.get(rng.nextInt(alarming.size()));
        HmiAlarmDTO a = new HmiAlarmDTO();
        a.setId("alm-" + seq.getAndIncrement());
        a.setTag(m.getKey());
        HmiAlarmSeverity sev;
        double excess = 0;
        if (m.getMax() != null && m.getValue() > m.getMax()) excess = m.getValue() - m.getMax();
        double range = Math.max(1.0, (m.getMax() == null ? 100 : m.getMax()) - (m.getMin() == null ? 0 : m.getMin()));
        double excessPct = excess / range;
        if (excessPct > 0.25) sev = HmiAlarmSeverity.CRITICAL;
        else if (excessPct > 0.10) sev = HmiAlarmSeverity.HIGH;
        else if (excessPct > 0.03) sev = HmiAlarmSeverity.MEDIUM;
        else sev = HmiAlarmSeverity.LOW;
        a.setSeverity(sev);
        a.setMessage(m.getName() + " out of band: " + m.getValue() + " " + (m.getUnit() == null ? "" : m.getUnit()));
        a.setTs(Instant.now());
        a.setAcknowledged(false);
        a.setSource("ProcessControl");
        // keep last 20 alarms max
        h.getAlarms().add(0, a);
        if (h.getAlarms().size() > 20) h.getAlarms().subList(20, h.getAlarms().size()).clear();

        Map<String, Object> env = new LinkedHashMap<>();
        env.put("kind", "ALARM");
        env.put("hmiId", h.getId());
        env.put("alarm", a);
        emit(env);
    }

    private void maybeAutoAckOldAlarms(FakeHmiInstanceDTO h) {
        Instant cutoff = Instant.now().minusSeconds(90);
        for (HmiAlarmDTO a : h.getAlarms()) {
            if (Boolean.FALSE.equals(a.getAcknowledged()) && a.getTs() != null && a.getTs().isBefore(cutoff)) {
                a.setAcknowledged(true);
            }
        }
    }

    private void recomputeThreatScore(FakeHmiInstanceDTO h) {
        List<HmiInteractionDTO> log = interactionLog.getOrDefault(h.getId(), Collections.emptyList());
        Instant cutoff = Instant.now().minusSeconds(24 * 3600);
        int score = 0;
        Set<String> ips = new HashSet<>();
        for (HmiInteractionDTO ix : log) {
            if (ix.getTs() == null || ix.getTs().isBefore(cutoff)) continue;
            ips.add(ix.getAttackerIp());
            switch (ix.getType()) {
                case CONTROL_WRITE -> score += 20;
                case LOGIN_ATTEMPT -> score += 8;
                case CONFIG_PROBE  -> score += 10;
                case ALARM_ACK     -> score += 5;
                case DATA_POLL     -> score += 2;
                case PAGE_VIEW     -> score += 1;
            }
        }
        score += Math.min(25, ips.size() * 3);
        h.setThreatScore(Math.min(100, score));
        h.setInteractions24h((long) log.stream()
                .filter(i -> i.getTs() != null && i.getTs().isAfter(cutoff)).count());
        h.setDistinctAttackers24h(ips.size());
    }

    // ==================================================================
    // Seeding (4 HMIs, one per scenario)
    // ==================================================================

    private void seedInstances() {
        instances.clear();
        hmiByType.clear();
        hmiBySiteTag.clear();

        // Persona definitions are pinned to the real docker-compose tripwire
        // fleet at /decoys/docker-compose.yml. IP / port / vendor / site_tag
        // mirror the live containers so recordTripwireHit() can resolve an
        // inbound /api/honeypot/ingest event back to the right HMI card.
        //
        //   HMI_TYPE         IP             PORT  VENDOR     HMI_SITE_TAG
        //   WATER_TREATMENT  172.30.50.11   502   SCHNEIDER  WATER-PLANT-A
        //   SUBSTATION       172.30.50.10   502   SIEMENS    SUBSTATION-NORTH-33KV
        //   REFINERY         172.30.50.12   2404  ABB        REFINERY-PIPELINE-PROFILE
        //   MANUFACTURING    172.30.50.13   102   ROCKWELL   ASSEMBLY-LINE-1

        // 1) Water Treatment - Schneider, Modbus 502 @ 172.30.50.11
        FakeHmiInstanceDTO water = hmi(
                "hmi-water-01", "North Water Plant HMI-02",
                HmiScenarioType.WATER_TREATMENT, HmiVariantStyle.SCHNEIDER,
                "Schneider Electric", "EcoStruxure Operator Terminal (Modbus TCP)", "V3.5 SP2",
                "172.30.50.11", 502, 2, "WATER-PLANT-A", 0.25, 0.60
        );
        water.setMetrics(new ArrayList<>(Arrays.asList(
                metric("tank1_level",  "Raw Water Tank Level",    "%",   72.5, 20,  95, "tank"),
                metric("tank2_level",  "Clearwell Tank Level",    "%",   58.2, 25,  90, "tank"),
                metric("chlorine_ppm", "Chlorine Dosage",         "ppm",  1.8, 0.5,  2.5, "gauge"),
                metric("ph",           "pH",                      "",     7.2, 6.5,  8.2, "gauge"),
                metric("flow_in",      "Raw Water Inflow",        "m³/h", 420,  0,  600, "flow"),
                metric("flow_out",     "Treated Water Outflow",   "m³/h", 395,  0,  600, "flow"),
                metric("pump1_rpm",    "Intake Pump RPM",         "rpm", 1430, 0, 1800, "pump"),
                metric("pump2_rpm",    "Chemical Dosing Pump",    "rpm",  860, 0, 1200, "pump"),
                metric("filter_dp",    "Filter ΔP",               "bar",  0.8,  0,  1.5, "pressure"),
                metric("turbidity",    "Effluent Turbidity",      "NTU",  0.4,  0,  1.0, "gauge")
        )));
        instances.put(water.getId(), water);
        hmiByType.put("WATER_TREATMENT", water.getId());
        hmiBySiteTag.put("WATER-PLANT-A", water.getId());

        // 2) Substation - Siemens, Modbus 502 @ 172.30.50.10
        FakeHmiInstanceDTO sub = hmi(
                "hmi-sub-01", "Substation K-12 Control",
                HmiScenarioType.SUBSTATION, HmiVariantStyle.SIEMENS,
                "Siemens", "SIMATIC WinCC OA (Modbus TCP)", "V3.18 P010",
                "172.30.50.10", 502, 2, "SUBSTATION-NORTH-33KV", 0.55, 0.35
        );
        sub.setMetrics(new ArrayList<>(Arrays.asList(
                metric("v_l1", "Phase L1 Voltage", "kV",  33.1, 31.0, 34.5, "voltage"),
                metric("v_l2", "Phase L2 Voltage", "kV",  33.0, 31.0, 34.5, "voltage"),
                metric("v_l3", "Phase L3 Voltage", "kV",  32.9, 31.0, 34.5, "voltage"),
                metric("i_l1", "Phase L1 Current", "A",  185, 0, 400, "current"),
                metric("i_l2", "Phase L2 Current", "A",  192, 0, 400, "current"),
                metric("i_l3", "Phase L3 Current", "A",  188, 0, 400, "current"),
                metric("freq", "Grid Frequency", "Hz", 50.02, 49.85, 50.15, "gauge"),
                metric("trafo_oil_temp", "Trafo Oil Temp", "°C", 52, 20, 75, "temp"),
                metric("sf6_pressure", "SF6 Pressure", "bar", 6.2, 5.8, 7.0, "pressure"),
                metric("breaker_1", "Breaker CB-101 Position", "", 1, 0, 1, "gauge")
        )));
        instances.put(sub.getId(), sub);
        hmiByType.put("SUBSTATION", sub.getId());
        hmiBySiteTag.put("SUBSTATION-NORTH-33KV", sub.getId());

        // 3) Oil & Gas / Refinery - ABB, IEC 60870-5-104 2404 @ 172.30.50.12
        FakeHmiInstanceDTO oil = hmi(
                "hmi-oil-01", "Refinery B Pipeline HMI",
                HmiScenarioType.OIL_GAS, HmiVariantStyle.ROCKWELL,
                "ABB", "800xA Operator Workplace (IEC 60870-5-104)", "V6.1.1",
                "172.30.50.12", 2404, 2, "REFINERY-PIPELINE-PROFILE", 0.70, 0.65
        );
        oil.setMetrics(new ArrayList<>(Arrays.asList(
                metric("pipe_p1",  "Segment P1 Pressure", "bar",  42, 20, 60, "pressure"),
                metric("pipe_p2",  "Segment P2 Pressure", "bar",  38, 20, 60, "pressure"),
                metric("pipe_p3",  "Segment P3 Pressure", "bar",  41, 20, 60, "pressure"),
                metric("valve_1",  "Isolation Valve V-101",  "",  1, 0, 1, "gauge"),
                metric("valve_2",  "Emergency Valve V-204",  "",  1, 0, 1, "gauge"),
                metric("pump_a",   "Pump Station A Flow", "m³/h", 210, 0, 400, "flow"),
                metric("pump_b",   "Pump Station B Flow", "m³/h", 198, 0, 400, "flow"),
                metric("tank_t1",  "Storage Tank T-1",    "%",  71, 10, 95, "tank"),
                metric("tank_t2",  "Storage Tank T-2",    "%",  64, 10, 95, "tank"),
                metric("lel",      "Gas Detector LEL",    "%",  2,  0, 10, "gauge")
        )));
        instances.put(oil.getId(), oil);
        hmiByType.put("REFINERY", oil.getId());
        hmiByType.put("OIL_GAS", oil.getId());          // backend scenario alias
        hmiBySiteTag.put("REFINERY-PIPELINE-PROFILE", oil.getId());

        // 4) Manufacturing - Rockwell, S7Comm 102 @ 172.30.50.13
        FakeHmiInstanceDTO mfg = hmi(
                "hmi-mfg-01", "Line-7 Assembly HMI",
                HmiScenarioType.MANUFACTURING, HmiVariantStyle.ROCKWELL,
                "Rockwell Automation", "FactoryTalk View SE (S7Comm)", "V12.00",
                "172.30.50.13", 102, 2, "ASSEMBLY-LINE-1", 0.40, 0.45
        );
        mfg.setMetrics(new ArrayList<>(Arrays.asList(
                metric("conveyor_rpm", "Conveyor Speed",     "rpm", 240, 180, 300, "pump"),
                metric("robot_cyc",    "Robot Cycle Time",   "s",   14.2, 10, 20, "gauge"),
                metric("oee",          "Overall Equipment Eff", "%", 82, 60, 100, "gauge"),
                metric("good_count",   "Good Units Counter", "",   1247, 0, 100000, "counter"),
                metric("reject_count", "Rejected Units",     "",    32, 0, 10000, "counter"),
                metric("temp_weld",    "Welder Temperature", "°C", 412, 300, 500, "temp"),
                metric("press_p1",     "Press Station 1",    "kN",  85, 40, 120, "pressure"),
                metric("press_p2",     "Press Station 2",    "kN",  88, 40, 120, "pressure"),
                metric("lube_psi",     "Lubricant Pressure", "bar", 3.1, 1.5, 5.0, "pressure"),
                metric("air_psi",      "Pneumatic Line",     "bar", 6.5, 5.0, 7.5, "pressure")
        )));
        instances.put(mfg.getId(), mfg);
        hmiByType.put("MANUFACTURING", mfg.getId());
        hmiBySiteTag.put("ASSEMBLY-LINE-1", mfg.getId());

        // Prime each with an initial innocuous alarm + a few interactions for visibility
        for (FakeHmiInstanceDTO h : instances.values()) {
            HmiAlarmDTO a = new HmiAlarmDTO();
            a.setId("alm-seed-" + h.getId());
            a.setSeverity(HmiAlarmSeverity.LOW);
            a.setMessage("Tripwire HMI on " + h.getIpAddress() + ":" + h.getPort()
                + " online — no inbound connections (healthy)");
            a.setTs(Instant.now().minusSeconds(120));
            a.setAcknowledged(true);
            a.setSource("Tripwire");
            h.getAlarms().add(a);
        }
    }

    private FakeHmiInstanceDTO hmi(String id, String name, HmiScenarioType scen, HmiVariantStyle var,
                                    String vendor, String model, String fw,
                                    String ip, int port, int purdue,
                                    String facility, double fx, double fy) {
        FakeHmiInstanceDTO h = new FakeHmiInstanceDTO();
        h.setId(id);
        h.setName(name);
        h.setScenario(scen);
        h.setVariant(var);
        h.setStatus(HmiStatus.RUNNING);
        h.setVendor(vendor);
        h.setModel(model);
        h.setFirmware(fw);
        h.setIpAddress(ip);
        h.setPort(port);
        h.setPurdueLevel(purdue);
        h.setFacility(facility);
        h.setFacilityX(fx);
        h.setFacilityY(fy);
        h.setTotalInteractions(0L);
        h.setInteractions24h(0L);
        h.setDistinctAttackers24h(0);
        h.setThreatScore(0);
        h.setUptimeSeconds(0L);
        return h;
    }

    private HmiMetricDTO metric(String key, String name, String unit, double value, double min, double max, String cat) {
        HmiMetricDTO m = new HmiMetricDTO();
        m.setKey(key);
        m.setName(name);
        m.setUnit(unit);
        m.setValue(value);
        m.setMin(min);
        m.setMax(max);
        m.setAlarming(false);
        m.setCategory(cat);
        m.setTrend(0);
        return m;
    }

    // ==================================================================
    // Helpers
    // ==================================================================

    /** Returns a shallow copy with copied metric/alarm lists (so mutations during serialization are safe). */
    private FakeHmiInstanceDTO shallowCopyForList(FakeHmiInstanceDTO src) {
        FakeHmiInstanceDTO out = new FakeHmiInstanceDTO();
        out.setId(src.getId());
        out.setName(src.getName());
        out.setScenario(src.getScenario());
        out.setVariant(src.getVariant());
        out.setStatus(src.getStatus());
        out.setVendor(src.getVendor());
        out.setModel(src.getModel());
        out.setFirmware(src.getFirmware());
        out.setIpAddress(src.getIpAddress());
        out.setPort(src.getPort());
        out.setPurdueLevel(src.getPurdueLevel());
        out.setFacility(src.getFacility());
        out.setFacilityX(src.getFacilityX());
        out.setFacilityY(src.getFacilityY());
        out.setMetrics(new ArrayList<>(src.getMetrics()));
        out.setAlarms(new ArrayList<>(src.getAlarms()));
        out.setTotalInteractions(src.getTotalInteractions());
        out.setInteractions24h(src.getInteractions24h());
        out.setDistinctAttackers24h(src.getDistinctAttackers24h());
        out.setLastAccessedAt(src.getLastAccessedAt());
        out.setThreatScore(src.getThreatScore());
        out.setUptimeSeconds(src.getUptimeSeconds());
        return out;
    }

    private static double round2(double v) { return Math.round(v * 100.0) / 100.0; }

    private static String truncate(String s, int n) {
        if (s == null) return null;
        return s.length() <= n ? s : s.substring(0, n) + "…";
    }

    private static String guessCountryForIp(String ip) {
        if (ip == null || ip.isBlank()) return null;
        // Naive deterministic mapping for demo: pick by first octet
        int first;
        try { first = Integer.parseInt(ip.split("\\.")[0]); } catch (Exception e) { return "??"; }
        String[] pool = {"RU", "CN", "IR", "KP", "US", "DE", "NL", "BR", "TR", "IN", "UA", "VN"};
        return pool[Math.floorMod(first, pool.length)];
    }
}
