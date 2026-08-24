package com.safetech.otshield.service.integration;

import com.safetech.otshield.model.Anomaly;
import com.safetech.otshield.repository.AnomalyRepository;
import com.safetech.otshield.service.decoy.BreachDetectedEvent;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Forwards OTShield security events to an external SIEM (Splunk, QRadar,
 * Sentinel, Wazuh, ...) as either RFC 5424 syslog or ArcSight CEF over UDP or
 * TCP. This is the "good citizen in an existing SOC" integration: OTShield does
 * not try to replace the SIEM, it pushes its high-value OT deception signals
 * into whatever the customer already runs.
 *
 * <p>Two real event sources, no fabrication:
 * <ul>
 *   <li>{@link BreachDetectedEvent} - twin writes and honeytoken trips, forwarded
 *       in real time (these are the crown-jewel, false-positive-free signals).</li>
 *   <li>Anomalies - a lightweight scheduled tail of {@link AnomalyRepository}
 *       forwards each new anomaly once, so the SOC sees the full detection
 *       stream without OTShield having to poll or block the detection path.</li>
 * </ul>
 *
 * <p>Config is held in memory (defaulted from application.properties) so no
 * schema change is needed; it survives a running process and is edited from the
 * SIEM Forwarding page. Sockets are opened per batch and closed - volumes here
 * are low (deception events are rare by design) so a connection pool is not
 * worth the failure surface.
 */
@Service
@Slf4j
public class SiemForwarderService {

    public enum Protocol { UDP, TCP }
    public enum Format { CEF, RFC5424 }

    // ---- live config (in-memory, defaulted from properties) ----
    private volatile boolean enabled;
    private volatile String host;
    private volatile int port;
    private volatile Protocol protocol;
    private volatile Format format;
    /** Minimum severity to forward: CRITICAL|HIGH|MEDIUM|LOW|INFO. */
    private volatile String minSeverity;

    private final AnomalyRepository anomalyRepository;

    // ---- runtime telemetry ----
    private final AtomicLong sent = new AtomicLong();
    private final AtomicLong failed = new AtomicLong();
    private final AtomicLong dropped = new AtomicLong(); // below threshold
    private volatile Instant lastSentAt;
    private volatile String lastError;
    private volatile String lastMessage;

    // anomaly tail checkpoint + a small dedup ring so a boundary anomaly is not sent twice
    private volatile LocalDateTime anomalyCheckpoint = LocalDateTime.now();
    private final Set<String> recentlyForwarded = ConcurrentHashMap.newKeySet();
    private final Deque<String> forwardOrder = new ArrayDeque<>();
    private static final int DEDUP_MAX = 1000;

    private static final DateTimeFormatter CEF_TS =
            DateTimeFormatter.ofPattern("MMM dd yyyy HH:mm:ss");

    public SiemForwarderService(
            AnomalyRepository anomalyRepository,
            @Value("${siem.forward.enabled:false}") boolean enabled,
            @Value("${siem.forward.host:}") String host,
            @Value("${siem.forward.port:514}") int port,
            @Value("${siem.forward.protocol:UDP}") String protocol,
            @Value("${siem.forward.format:CEF}") String format,
            @Value("${siem.forward.min-severity:LOW}") String minSeverity) {
        this.anomalyRepository = anomalyRepository;
        this.enabled = enabled;
        this.host = host == null ? "" : host.trim();
        this.port = port;
        this.protocol = parseProtocol(protocol);
        this.format = parseFormat(format);
        this.minSeverity = normalizeSeverity(minSeverity);
    }

    // ------------------------------------------------------------------
    // Event sources
    // ------------------------------------------------------------------

    /** Real-time forward of deception breach signals. */
    @EventListener
    public void onBreach(BreachDetectedEvent e) {
        if (!enabled) return;
        try {
            boolean honeytoken = "HONEYTOKEN_TRIP".equals(e.getTrigger());
            // Deception breaches are always high-confidence; treat as HIGH.
            String severity = "HIGH";
            SiemEvent ev = new SiemEvent();
            ev.category = honeytoken ? "honeytoken-trip" : "decoy-twin-write";
            ev.signatureId = honeytoken ? "OT-DECEPTION-HONEYTOKEN" : "OT-DECEPTION-TWIN-WRITE";
            ev.name = honeytoken
                    ? "Honeytoken tripped on the deception fabric"
                    : "Attacker wrote to a decoy OT twin";
            ev.severity = severity;
            ev.sourceIp = e.getSourceIp();
            ev.destinationName = e.getAssetName();
            ev.protocol = e.getProtocol();
            ev.message = summarize(e);
            ev.ts = Instant.now();
            ev.ext.put("otTrigger", e.getTrigger());
            if (e.getAssetId() != null) ev.ext.put("otAssetId", e.getAssetId());
            if (e.getDetail() != null) ev.ext.put("otDetail", e.getDetail());
            deliver(ev);
        } catch (Exception ex) {
            log.warn("SIEM breach forward failed: {}", ex.getMessage());
        }
    }

    /** Scheduled tail of newly created anomalies (once each). */
    @Scheduled(fixedDelayString = "${siem.forward.poll-ms:30000}", initialDelay = 20000)
    public void forwardNewAnomalies() {
        if (!enabled || host.isBlank()) return;
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime since = anomalyCheckpoint;
        try {
            List<Anomaly> fresh = anomalyRepository.findByCreatedAtBetween(since, now);
            for (Anomaly a : fresh) {
                if (a.getId() == null || !markForwarded(a.getId())) continue;
                try {
                    deliver(fromAnomaly(a));
                } catch (Exception ex) {
                    // markForwarded already recorded it; deliver() bumped failed
                    log.debug("Anomaly {} forward error: {}", a.getId(), ex.getMessage());
                }
            }
        } catch (Exception ex) {
            log.warn("SIEM anomaly tail failed: {}", ex.getMessage());
        } finally {
            anomalyCheckpoint = now;
        }
    }

    // ------------------------------------------------------------------
    // Config API (used by the controller / UI)
    // ------------------------------------------------------------------

    public synchronized Map<String, Object> getConfig() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enabled", enabled);
        m.put("host", host);
        m.put("port", port);
        m.put("protocol", protocol.name());
        m.put("format", format.name());
        m.put("minSeverity", minSeverity);
        return m;
    }

    public synchronized Map<String, Object> updateConfig(Map<String, Object> req) {
        if (req.containsKey("enabled")) this.enabled = Boolean.parseBoolean(String.valueOf(req.get("enabled")));
        if (req.containsKey("host")) this.host = String.valueOf(req.getOrDefault("host", "")).trim();
        if (req.containsKey("port")) {
            try { this.port = Integer.parseInt(String.valueOf(req.get("port")).trim()); }
            catch (NumberFormatException ignore) { /* keep previous */ }
        }
        if (req.containsKey("protocol")) this.protocol = parseProtocol(String.valueOf(req.get("protocol")));
        if (req.containsKey("format")) this.format = parseFormat(String.valueOf(req.get("format")));
        if (req.containsKey("minSeverity")) this.minSeverity = normalizeSeverity(String.valueOf(req.get("minSeverity")));
        log.info("SIEM forwarding config updated: enabled={} {}://{}:{} format={} minSeverity={}",
                enabled, protocol, host, port, format, minSeverity);
        return getConfig();
    }

    public Map<String, Object> stats() {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("enabled", enabled);
        m.put("target", host.isBlank() ? null : (protocol + "://" + host + ":" + port));
        m.put("format", format.name());
        m.put("minSeverity", minSeverity);
        m.put("sent", sent.get());
        m.put("failed", failed.get());
        m.put("droppedBelowThreshold", dropped.get());
        m.put("lastSentAt", lastSentAt == null ? null : lastSentAt.toString());
        m.put("lastError", lastError);
        m.put("lastMessage", lastMessage);
        return m;
    }

    /** Send a synthetic test event to the configured target. Returns result detail. */
    public synchronized Map<String, Object> sendTest() {
        Map<String, Object> res = new LinkedHashMap<>();
        if (host.isBlank()) {
            res.put("ok", false);
            res.put("error", "No SIEM host configured");
            return res;
        }
        SiemEvent ev = new SiemEvent();
        ev.category = "test";
        ev.signatureId = "OT-SIEM-TEST";
        ev.name = "OTShield SIEM forwarding test event";
        ev.severity = "INFO";
        ev.sourceIp = "127.0.0.1";
        ev.protocol = "TEST";
        ev.message = "If you can see this in your SIEM, OTShield forwarding is wired correctly.";
        ev.ts = Instant.now();
        String wire = render(ev);
        try {
            send(wire);
            sent.incrementAndGet();
            lastSentAt = Instant.now();
            lastMessage = wire;
            lastError = null;
            res.put("ok", true);
            res.put("target", protocol + "://" + host + ":" + port);
            res.put("format", format.name());
            res.put("sample", wire);
        } catch (Exception ex) {
            failed.incrementAndGet();
            lastError = ex.getClass().getSimpleName() + ": " + ex.getMessage();
            res.put("ok", false);
            res.put("error", lastError);
            res.put("sample", wire);
        }
        return res;
    }

    // ------------------------------------------------------------------
    // Delivery
    // ------------------------------------------------------------------

    private void deliver(SiemEvent ev) {
        if (host.isBlank()) return;
        if (severityRank(ev.severity) < severityRank(minSeverity)) {
            dropped.incrementAndGet();
            return;
        }
        String wire = render(ev);
        try {
            send(wire);
            sent.incrementAndGet();
            lastSentAt = Instant.now();
            lastMessage = wire;
            lastError = null;
        } catch (Exception ex) {
            failed.incrementAndGet();
            lastError = ex.getClass().getSimpleName() + ": " + ex.getMessage();
            log.warn("SIEM send failed to {}:{} - {}", host, port, lastError);
        }
    }

    private void send(String message) throws Exception {
        byte[] payload = message.getBytes(StandardCharsets.UTF_8);
        if (protocol == Protocol.UDP) {
            try (DatagramSocket socket = new DatagramSocket()) {
                InetAddress addr = InetAddress.getByName(host);
                DatagramPacket packet = new DatagramPacket(payload, payload.length, addr, port);
                socket.send(packet);
            }
        } else {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(host, port), 4000);
                OutputStream out = socket.getOutputStream();
                out.write(payload);
                if (payload.length == 0 || payload[payload.length - 1] != '\n') {
                    out.write('\n'); // octet-stream framing: newline-delimited
                }
                out.flush();
            }
        }
    }

    // ------------------------------------------------------------------
    // Formatting
    // ------------------------------------------------------------------

    private String render(SiemEvent ev) {
        return format == Format.CEF ? renderCef(ev) : renderRfc5424(ev);
    }

    /** ArcSight CEF: CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extensions */
    private String renderCef(SiemEvent ev) {
        StringBuilder ext = new StringBuilder();
        appendCefKv(ext, "rt", CEF_TS.format(ev.ts.atZone(ZoneId.systemDefault())));
        if (ev.sourceIp != null) appendCefKv(ext, "src", ev.sourceIp);
        if (ev.destinationName != null) appendCefKv(ext, "dhost", ev.destinationName);
        if (ev.protocol != null) appendCefKv(ext, "proto", ev.protocol);
        if (ev.category != null) appendCefKv(ext, "cat", ev.category);
        if (ev.message != null) appendCefKv(ext, "msg", ev.message);
        for (Map.Entry<String, String> e : ev.ext.entrySet()) {
            appendCefKv(ext, e.getKey(), e.getValue());
        }
        // header fields escape only backslash and pipe
        return "CEF:0|OTShield|OT Deception Platform|1.0|"
                + cefHeader(ev.signatureId) + "|"
                + cefHeader(ev.name) + "|"
                + cefSeverity(ev.severity) + "|"
                + ext;
    }

    /** RFC 5424 syslog: <PRI>1 TIMESTAMP HOST APP - MSGID [SD] MSG */
    private String renderRfc5424(SiemEvent ev) {
        int pri = 16 * 8 + syslogSeverity(ev.severity); // facility local0
        // Structured data with the key OT fields, then a human message.
        StringBuilder sd = new StringBuilder("[otshield@32473");
        sd.append(" event=\"").append(sdEscape(ev.signatureId)).append("\"");
        sd.append(" severity=\"").append(sdEscape(ev.severity)).append("\"");
        if (ev.sourceIp != null) sd.append(" src=\"").append(sdEscape(ev.sourceIp)).append("\"");
        if (ev.destinationName != null) sd.append(" dst=\"").append(sdEscape(ev.destinationName)).append("\"");
        if (ev.protocol != null) sd.append(" proto=\"").append(sdEscape(ev.protocol)).append("\"");
        if (ev.category != null) sd.append(" category=\"").append(sdEscape(ev.category)).append("\"");
        for (Map.Entry<String, String> e : ev.ext.entrySet()) {
            sd.append(" ").append(e.getKey()).append("=\"").append(sdEscape(e.getValue())).append("\"");
        }
        sd.append("]");
        String msg = (ev.name == null ? "" : ev.name) + (ev.message == null ? "" : " - " + ev.message);
        return "<" + pri + ">1 " + isoUtc(ev.ts) + " otshield otshield - " + ev.signatureId + " " + sd + " " + msg;
    }

    // ------------------------------------------------------------------
    // Mapping helpers
    // ------------------------------------------------------------------

    private SiemEvent fromAnomaly(Anomaly a) {
        SiemEvent ev = new SiemEvent();
        ev.category = "anomaly";
        ev.signatureId = a.getMitreId() != null && !a.getMitreId().isBlank()
                ? a.getMitreId() : "OT-ANOMALY";
        ev.name = a.getTitle() != null ? a.getTitle() : "OT anomaly detected";
        ev.severity = a.getSeverity() != null ? a.getSeverity().name() : "MEDIUM";
        ev.sourceIp = a.getSourceIp();
        ev.destinationName = a.getDestinationIp();
        ev.protocol = a.getProtocol();
        ev.message = a.getDescription();
        ev.ts = a.getCreatedAt() != null
                ? a.getCreatedAt().atZone(ZoneId.systemDefault()).toInstant()
                : Instant.now();
        if (a.getMitreTactic() != null) ev.ext.put("otMitreTactic", a.getMitreTactic());
        if (a.getMitreTechnique() != null) ev.ext.put("otMitreTechnique", a.getMitreTechnique());
        if (a.getAnomalyType() != null) ev.ext.put("otAnomalyType", a.getAnomalyType().name());
        if (a.getRiskScore() != null) ev.ext.put("otRiskScore", String.valueOf(a.getRiskScore()));
        if (a.getPurdueLevel() != null) ev.ext.put("otPurdueLevel", a.getPurdueLevel());
        if (a.getDestinationPort() != null) ev.ext.put("dpt", String.valueOf(a.getDestinationPort()));
        if (a.getSourcePort() != null) ev.ext.put("spt", String.valueOf(a.getSourcePort()));
        return ev;
    }

    private String summarize(BreachDetectedEvent e) {
        if ("HONEYTOKEN_TRIP".equals(e.getTrigger())) {
            return "Honeytoken tripped by " + e.getSourceIp()
                    + (e.getDetail() != null ? " (" + e.getDetail() + ")" : "");
        }
        return (e.getDetail() != null ? e.getDetail() + " " : "Write ")
                + "against decoy twin of "
                + (e.getAssetName() != null ? e.getAssetName() : e.getProtocol())
                + " from " + e.getSourceIp();
    }

    private boolean markForwarded(String id) {
        if (!recentlyForwarded.add(id)) return false;
        synchronized (forwardOrder) {
            forwardOrder.addLast(id);
            while (forwardOrder.size() > DEDUP_MAX) {
                String old = forwardOrder.pollFirst();
                if (old != null) recentlyForwarded.remove(old);
            }
        }
        return true;
    }

    // severity ordering: higher rank = more severe
    private int severityRank(String s) {
        switch (normalizeSeverity(s)) {
            case "CRITICAL": return 5;
            case "HIGH": return 4;
            case "MEDIUM": return 3;
            case "LOW": return 2;
            default: return 1; // INFO
        }
    }

    // CEF 0-10 scale
    private int cefSeverity(String s) {
        switch (normalizeSeverity(s)) {
            case "CRITICAL": return 10;
            case "HIGH": return 8;
            case "MEDIUM": return 5;
            case "LOW": return 3;
            default: return 1;
        }
    }

    // syslog severity 0(emerg)-7(debug)
    private int syslogSeverity(String s) {
        switch (normalizeSeverity(s)) {
            case "CRITICAL": return 2; // crit
            case "HIGH": return 3;     // err
            case "MEDIUM": return 4;   // warning
            case "LOW": return 5;      // notice
            default: return 6;         // info
        }
    }

    private String normalizeSeverity(String s) {
        if (s == null) return "INFO";
        String u = s.trim().toUpperCase();
        switch (u) {
            case "CRITICAL": case "HIGH": case "MEDIUM": case "LOW": case "INFO": return u;
            default: return "INFO";
        }
    }

    private Protocol parseProtocol(String p) {
        try { return Protocol.valueOf(p.trim().toUpperCase()); }
        catch (Exception e) { return Protocol.UDP; }
    }

    private Format parseFormat(String f) {
        try { return Format.valueOf(f.trim().toUpperCase()); }
        catch (Exception e) { return Format.CEF; }
    }

    private String isoUtc(Instant ts) {
        return DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
                .withZone(ZoneOffset.UTC).format(ts);
    }

    private void appendCefKv(StringBuilder sb, String k, String v) {
        if (v == null) return;
        if (sb.length() > 0) sb.append(' ');
        sb.append(k).append('=').append(cefValue(v));
    }

    // CEF header escaping: backslash and pipe
    private String cefHeader(String v) {
        if (v == null) return "";
        return v.replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ").replace("\r", " ");
    }

    // CEF extension value escaping: backslash, equals, newlines
    private String cefValue(String v) {
        if (v == null) return "";
        return v.replace("\\", "\\\\").replace("=", "\\=").replace("\n", " ").replace("\r", " ");
    }

    private String sdEscape(String v) {
        if (v == null) return "";
        return v.replace("\\", "\\\\").replace("\"", "\\\"").replace("]", "\\]")
                .replace("\n", " ").replace("\r", " ");
    }

    /** Internal, normalized event carrier - not persisted, not a DTO. */
    private static final class SiemEvent {
        String category;
        String signatureId;
        String name;
        String severity;
        String sourceIp;
        String destinationName;
        String protocol;
        String message;
        Instant ts = Instant.now();
        final Map<String, String> ext = new LinkedHashMap<>();
    }
}
