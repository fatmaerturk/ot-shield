package com.safetech.otshield.service;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.stream.Collectors;

/**
 * Tracks live-ingestion activity so the UI can show WHO is feeding the platform
 * and HOW MUCH, without fabricating anything: every data point here is a real
 * {@code POST /api/upload/pcap} that actually hit the analysis pipeline. A SPAN
 * sensor (see {@code sensor/span_sensor.py}) uploads rolling pcaps and tags each
 * with an {@code X-Sensor-Id} header; manual browser uploads show up as the
 * {@code manual-upload} sensor.
 *
 * In-memory + bounded (lost on restart, repopulates within one rotation window
 * as sensors keep POSTing). A durable ingestion_events table is the later step.
 */
@Service
public class IngestionMonitorService {

    /** How many recent ingest events to retain for the feed + rolling windows. */
    public static final int MAX_EVENTS = 500;
    /** A sensor is "online" if it uploaded within this window. */
    private static final long ONLINE_WINDOW_MS = 180_000L; // 3 min

    /** One recorded upload, with what the pipeline found in it. */
    public record IngestEvent(long ts, String sensorId, String host, String iface,
                              String remoteIp, String filename, long bytes,
                              int packets, boolean parsed, int newAssets, int newAnomalies,
                              List<String> protocols) {}

    // Newest first (addFirst); bounded by MAX_EVENTS.
    private final Deque<IngestEvent> events = new ConcurrentLinkedDeque<>();

    private static String nz(String s) { return (s == null || s.isBlank()) ? "" : s.trim(); }

    /** Record one upload plus the pipeline findings. Called from the pcap upload path. */
    public void track(String sensorId, String host, String iface, String remoteIp,
                      String filename, long bytes, int packets, boolean parsed,
                      int newAssets, int newAnomalies, List<String> protocols) {
        String sid = nz(sensorId);
        if (sid.isEmpty()) sid = "manual-upload";
        List<String> protos = (protocols == null) ? List.of()
                : protocols.stream().filter(p -> p != null && !p.isBlank())
                        .map(String::trim).distinct().collect(Collectors.toList());
        events.addFirst(new IngestEvent(System.currentTimeMillis(), sid, nz(host), nz(iface),
                nz(remoteIp), nz(filename), Math.max(0, bytes), Math.max(0, packets), parsed,
                Math.max(0, newAssets), Math.max(0, newAnomalies), protos));
        while (events.size() > MAX_EVENTS) events.pollLast();
    }

    /** The recent ingest feed, newest first. */
    public List<Map<String, Object>> recent(int limit) {
        int cap = Math.max(1, Math.min(limit, MAX_EVENTS));
        List<Map<String, Object>> out = new ArrayList<>();
        for (IngestEvent e : events) {
            out.add(eventMap(e));
            if (out.size() >= cap) break;
        }
        return out;
    }

    /** Per-sensor status + aggregate counters, over the retained window. */
    public Map<String, Object> summary() {
        long now = System.currentTimeMillis();
        // events iterate newest-first, so each group's list stays newest-first.
        Map<String, List<IngestEvent>> bySensor = events.stream()
                .collect(Collectors.groupingBy(IngestEvent::sensorId, LinkedHashMap::new, Collectors.toList()));

        List<Map<String, Object>> sensors = new ArrayList<>();
        long aggPacketsPerMin = 0;
        long aggBytes = 0;
        long aggPackets = 0;
        long aggAssets = 0;
        long aggAnomalies = 0;
        Set<String> allProtocols = new TreeSet<>();
        int online = 0;

        for (Map.Entry<String, List<IngestEvent>> en : bySensor.entrySet()) {
            List<IngestEvent> evs = en.getValue();
            IngestEvent last = evs.get(0);
            boolean isOnline = (now - last.ts()) <= ONLINE_WINDOW_MS;
            if (isOnline) online++;

            long packetsLastMin = 0, packets5m = 0, bytes = 0, packets = 0;
            long sAssets = 0, sAnomalies = 0;
            Set<String> sProtocols = new TreeSet<>();
            for (IngestEvent e : evs) {
                bytes += e.bytes();
                packets += e.packets();
                sAssets += e.newAssets();
                sAnomalies += e.newAnomalies();
                if (e.protocols() != null) sProtocols.addAll(e.protocols());
                if (now - e.ts() <= 60_000L) packetsLastMin += e.packets();
                if (now - e.ts() <= 300_000L) packets5m += e.packets();
            }
            aggPacketsPerMin += packetsLastMin;
            aggBytes += bytes;
            aggPackets += packets;
            aggAssets += sAssets;
            aggAnomalies += sAnomalies;
            allProtocols.addAll(sProtocols);

            Map<String, Object> s = new LinkedHashMap<>();
            s.put("sensorId", en.getKey());
            s.put("host", last.host());
            s.put("iface", last.iface());
            s.put("remoteIp", last.remoteIp());
            s.put("online", isOnline);
            s.put("lastSeen", last.ts());
            s.put("uploads", evs.size());
            s.put("packets", packets);
            s.put("bytes", bytes);
            s.put("packetsLastMin", packetsLastMin);
            s.put("packets5m", packets5m);
            s.put("lastFilename", last.filename());
            s.put("lastPackets", last.packets());
            s.put("lastParsed", last.parsed());
            s.put("newAssets", sAssets);
            s.put("newAnomalies", sAnomalies);
            s.put("protocols", new ArrayList<>(sProtocols));
            sensors.add(s);
        }
        // Online sensors first, then most-recently-seen.
        sensors.sort((a, b) -> {
            int byOnline = Boolean.compare((Boolean) b.get("online"), (Boolean) a.get("online"));
            if (byOnline != 0) return byOnline;
            return Long.compare((Long) b.get("lastSeen"), (Long) a.get("lastSeen"));
        });

        Map<String, Object> out = new LinkedHashMap<>();
        out.put("sensors", sensors);
        out.put("totalSensors", bySensor.size());
        out.put("onlineSensors", online);
        out.put("packetsPerMin", aggPacketsPerMin);
        out.put("windowPackets", aggPackets);
        out.put("windowBytes", aggBytes);
        out.put("windowAssets", aggAssets);
        out.put("windowAnomalies", aggAnomalies);
        out.put("protocols", new ArrayList<>(allProtocols));
        out.put("windowEvents", events.size());
        out.put("retainedMax", MAX_EVENTS);
        return out;
    }

    private Map<String, Object> eventMap(IngestEvent e) {
        Map<String, Object> m = new LinkedHashMap<>();
        m.put("ts", e.ts());
        m.put("sensorId", e.sensorId());
        m.put("host", e.host());
        m.put("iface", e.iface());
        m.put("remoteIp", e.remoteIp());
        m.put("filename", e.filename());
        m.put("bytes", e.bytes());
        m.put("packets", e.packets());
        m.put("parsed", e.parsed());
        m.put("newAssets", e.newAssets());
        m.put("newAnomalies", e.newAnomalies());
        m.put("protocols", e.protocols());
        return m;
    }
}
