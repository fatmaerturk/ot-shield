package com.safetech.otshield.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.safetech.otshield.service.fakehmi.FakeHmiService;
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

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * /ws/deception/hmi-stream
 *
 * Broadcasts fake-HMI events to subscribed UIs:
 *   { kind: "METRIC_UPDATE",  hmiId, metrics }
 *   { kind: "ALARM",          hmiId, alarm }
 *   { kind: "INTERACTION",    hmiId, interaction }
 *   { kind: "PING",           ts }
 *
 * Subscribes to FakeHmiService's Listener hook and relays envelopes out.
 */
@Component
public class FakeHmiStreamHandler extends TextWebSocketHandler {

    private static final Logger log = LoggerFactory.getLogger(FakeHmiStreamHandler.class);

    private final ObjectMapper mapper = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    private final CopyOnWriteArrayList<WebSocketSession> sessions = new CopyOnWriteArrayList<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
        Thread t = new Thread(r, "fakehmi-ws");
        t.setDaemon(true);
        return t;
    });

    private FakeHmiService hmiService;
    private FakeHmiService.Listener listener;

    @Autowired
    public void setHmiService(@Lazy FakeHmiService hmiService) {
        this.hmiService = hmiService;
    }

    @PostConstruct
    void start() {
        listener = this::broadcast;
        if (hmiService != null) hmiService.addListener(listener);
        scheduler.scheduleAtFixedRate(this::ping, 10, 30, TimeUnit.SECONDS);
    }

    @PreDestroy
    void stop() {
        scheduler.shutdownNow();
        if (hmiService != null && listener != null) hmiService.removeListener(listener);
        for (WebSocketSession s : sessions) {
            try { if (s.isOpen()) s.close(CloseStatus.GOING_AWAY); } catch (Exception ignored) {}
        }
        sessions.clear();
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        sessions.add(session);
        try {
            Map<String, Object> hello = new LinkedHashMap<>();
            hello.put("kind", "CONNECTED");
            hello.put("sessionId", session.getId());
            session.sendMessage(new TextMessage(mapper.writeValueAsString(hello)));
        } catch (Exception e) {
            log.warn("hmi ws welcome send failed: {}", e.getMessage());
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        sessions.remove(session);
    }

    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) {
        log.warn("hmi ws transport error: {}", exception.getMessage());
        sessions.remove(session);
    }

    public void broadcast(Map<String, Object> envelope) {
        if (sessions.isEmpty()) return;
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
            log.warn("hmi ws broadcast serialise failed: {}", e.getMessage());
        }
    }

    private void ping() {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("kind", "PING");
        p.put("ts", System.currentTimeMillis());
        broadcast(p);
    }
}
