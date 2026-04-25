package com.safetech.otshield.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.safetech.otshield.dto.decoy.EngagementDTO;
import com.safetech.otshield.dto.decoy.EngagementEventDTO;
import com.safetech.otshield.service.decoy.DecoyService;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * /ws/decoy/stream
 *
 * Broadcasts decoy-layer events to subscribed UIs:
 *   { kind: "EVENT",                event: EngagementEventDTO, engagementId }
 *   { kind: "ENGAGEMENT_STARTED",   engagement: EngagementDTO }
 *   { kind: "ENGAGEMENT_CLOSED",    engagementId }
 *   { kind: "INSTANCE_STATUS",      instanceId, status }
 *   { kind: "PING",                 ts }
 *
 * Currently driven by a scheduled simulator that picks a random active engagement
 * and emits a synthetic event every few seconds, so the UI behaves realistically
 * without a real Conpot capture loop attached.
 */
@Component
public class DecoyStreamHandler extends TextWebSocketHandler {

    private static final Logger log = LoggerFactory.getLogger(DecoyStreamHandler.class);

    private final ObjectMapper mapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private final CopyOnWriteArrayList<WebSocketSession> sessions = new CopyOnWriteArrayList<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
    private final Random rng = new Random();

    private DecoyService decoyService;

    @Autowired
    public void setDecoyService(@Lazy DecoyService decoyService) {
        this.decoyService = decoyService;
    }

    @PostConstruct
    void start() {
        scheduler.scheduleAtFixedRate(this::tick, 3, 4, TimeUnit.SECONDS);
        scheduler.scheduleAtFixedRate(this::ping,  10, 30, TimeUnit.SECONDS);
    }

    @PreDestroy
    void stop() {
        scheduler.shutdownNow();
        for (WebSocketSession s : sessions) {
            try { if (s.isOpen()) s.close(CloseStatus.GOING_AWAY); } catch (Exception ignored) {}
        }
        sessions.clear();
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        sessions.add(session);
        try {
            session.sendMessage(new TextMessage(mapper.writeValueAsString(Map.of(
                    "kind", "CONNECTED",
                    "sessionId", session.getId()
            ))));
        } catch (Exception e) {
            log.warn("welcome send failed: {}", e.getMessage());
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        sessions.remove(session);
    }

    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) {
        log.warn("decoy stream transport error: {}", exception.getMessage());
        sessions.remove(session);
    }

    /** External callers (e.g. ConpotLogIntegrationService) can publish here. */
    public void broadcast(Map<String, Object> envelope) {
        try {
            String json = mapper.writeValueAsString(envelope);
            TextMessage msg = new TextMessage(json);
            sessions.removeIf(s -> {
                try {
                    if (s.isOpen()) { s.sendMessage(msg); return false; }
                    return true;
                } catch (Exception ex) {
                    return true;
                }
            });
        } catch (Exception e) {
            log.warn("broadcast serialise failed: {}", e.getMessage());
        }
    }

    private void ping() {
        broadcast(Map.of("kind", "PING", "ts", System.currentTimeMillis()));
    }

    private void tick() {
        if (sessions.isEmpty() || decoyService == null) return;
        try {
            List<EngagementDTO> active = decoyService.listEngagements("ACTIVE", null, 0, 50);
            if (active.isEmpty()) return;
            EngagementDTO chosen = active.get(rng.nextInt(active.size()));
            EngagementDTO full = decoyService.getEngagement(chosen.getId());
            if (full == null || full.getEvents() == null || full.getEvents().isEmpty()) return;
            EngagementEventDTO sample = full.getEvents().get(rng.nextInt(full.getEvents().size()));
            broadcast(Map.of(
                    "kind", "EVENT",
                    "engagementId", full.getId(),
                    "decoyInstanceId", full.getDecoyInstanceId(),
                    "event", sample
            ));
        } catch (Exception e) {
            log.debug("tick failed: {}", e.getMessage());
        }
    }
}
