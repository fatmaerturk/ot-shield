package com.safetech.otshield.service;

import com.safetech.otshield.model.HoneypotLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Fans out newly persisted honeypot logs to all connected Attack Intelligence
 * clients over Server-Sent Events. Each browser tab opens a single long-lived
 * GET /api/honeypot/events stream and receives one "attack" event per real
 * persisted hit — the map animation is driven by these events instead of the
 * previous ambient-storm timer, so arc spawns correspond to real telemetry.
 */
@Service
public class HoneypotEventPublisher {

    private static final Logger log = LoggerFactory.getLogger(HoneypotEventPublisher.class);

    private final CopyOnWriteArrayList<SseEmitter> emitters = new CopyOnWriteArrayList<>();
    private final ScheduledExecutorService heartbeat = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "honeypot-sse-heartbeat");
        t.setDaemon(true);
        return t;
    });
    private final GeoIpService geoIpService;

    public HoneypotEventPublisher(GeoIpService geoIpService) {
        this.geoIpService = geoIpService;
        // Keep idle proxies / load balancers from closing the SSE stream.
        heartbeat.scheduleAtFixedRate(this::sendHeartbeat, 20, 20, TimeUnit.SECONDS);
    }

    public SseEmitter register() {
        SseEmitter emitter = new SseEmitter(0L); // no timeout — clients hold the connection
        emitters.add(emitter);
        emitter.onCompletion(() -> emitters.remove(emitter));
        emitter.onTimeout(() -> { emitters.remove(emitter); emitter.complete(); });
        emitter.onError(e -> emitters.remove(emitter));
        try {
            emitter.send(SseEmitter.event().name("ready").data("ok"));
        } catch (IOException e) {
            emitters.remove(emitter);
        }
        return emitter;
    }

    public void publish(HoneypotLog hp) {
        if (hp == null || emitters.isEmpty()) return;
        Map<String, Object> payload = toPayload(hp);
        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event().name("attack").data(payload));
            } catch (IOException | IllegalStateException e) {
                emitters.remove(emitter);
            }
        }
    }

    private void sendHeartbeat() {
        if (emitters.isEmpty()) return;
        for (SseEmitter emitter : emitters) {
            try {
                emitter.send(SseEmitter.event().comment("ping"));
            } catch (IOException | IllegalStateException e) {
                emitters.remove(emitter);
            }
        }
    }

    private Map<String, Object> toPayload(HoneypotLog hp) {
        Map<String, Object> m = new HashMap<>();
        m.put("id", hp.getId());
        m.put("sourceIp", hp.getSourceIp());
        m.put("protocol", hp.getProtocol());
        m.put("attackType", hp.getAttackType());
        m.put("severity", hp.getSeverity());
        m.put("country", hp.getCountry());
        m.put("city", hp.getCity());
        m.put("destinationPort", hp.getDestinationPort());
        m.put("timestamp", hp.getTimestamp() != null ? hp.getTimestamp().toString() : null);
        m.put("blocked", Boolean.TRUE.equals(hp.getIsBlocked()));
        // Resolve lat/lon so the map can position the arc origin even for an
        // IP that's not yet in the top-15 cached list on the frontend.
        GeoIpService.GeoInfo geo = geoIpService.lookup(hp.getSourceIp());
        m.put("lat", geo.lat);
        m.put("lon", geo.lon);
        return m;
    }
}
