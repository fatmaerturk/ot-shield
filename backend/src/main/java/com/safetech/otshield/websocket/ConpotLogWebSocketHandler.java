package com.safetech.otshield.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.safetech.otshield.service.ConpotService;
import com.safetech.otshield.event.ConpotStatusEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;

import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

@Component
public class ConpotLogWebSocketHandler extends TextWebSocketHandler {
    
    private static final Logger logger = LoggerFactory.getLogger(ConpotLogWebSocketHandler.class);
    
    @Autowired
    private ConpotService conpotService;
    
    private final Map<String, WebSocketSession> sessions = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
    private final ObjectMapper objectMapper = new ObjectMapper();
    
    private int lastLogCount = 0;
    private final Object sessionLock = new Object();
    private volatile long lastStatusUpdate = 0;
    private static final long STATUS_UPDATE_THROTTLE = 1000; // 1 second throttle
    private static final int SESSION_TIMEOUT = 30000; // 30 seconds timeout
    
    public ConpotLogWebSocketHandler() {
        // Start periodic broadcast of logs - less frequent to avoid WebSocket issues
        scheduler.scheduleAtFixedRate(this::broadcastLogs, 2, 3, TimeUnit.SECONDS);
        
        // Start heartbeat to clean up dead sessions
        scheduler.scheduleAtFixedRate(this::cleanupDeadSessions, 10, 30, TimeUnit.SECONDS);
        
        // Start heartbeat to keep connections alive
        scheduler.scheduleAtFixedRate(this::sendHeartbeat, 15, 60, TimeUnit.SECONDS);
    }
    
    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        logger.info("Conpot log WebSocket connection established: {}", session.getId());
        
        synchronized (sessionLock) {
            sessions.put(session.getId(), session);
        }
        
        try {
            // Send initial status
            sendStatus(session);
        } catch (Exception e) {
            logger.error("Error sending initial status to session: {}", session.getId(), e);
            synchronized (sessionLock) {
                sessions.remove(session.getId());
            }
            try {
                session.close();
            } catch (Exception closeException) {
                logger.debug("Error closing session after initial status error: {}", session.getId(), closeException);
            }
        }
    }
    
    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
        logger.info("Conpot log WebSocket connection closed: {} with status: {}", session.getId(), status);
        synchronized (sessionLock) {
            sessions.remove(session.getId());
        }
    }
    
    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) throws Exception {
        logger.warn("WebSocket transport error for session: {} - {}", session.getId(), exception.getMessage());
        synchronized (sessionLock) {
            sessions.remove(session.getId());
        }
        try {
            session.close();
        } catch (Exception e) {
            logger.debug("Error closing session after transport error: {}", session.getId(), e);
        }
    }
    
    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        try {
            String payload = message.getPayload();
            logger.debug("Received WebSocket message: {}", payload);
            
            // Handle different message types
            if ("get_status".equals(payload)) {
                sendStatus(session);
            } else if ("get_logs".equals(payload)) {
                sendAllLogs(session);
            }
        } catch (Exception e) {
            logger.error("Error handling WebSocket message from session: {}", session.getId(), e);
            try {
                session.close();
            } catch (Exception closeException) {
                logger.debug("Error closing session after message handling error: {}", session.getId(), closeException);
            }
        }
    }
    
    private void broadcastLogs() {
        synchronized (sessionLock) {
            if (sessions.isEmpty()) {
                return;
            }
        }
        
        try {
            var currentLogs = conpotService.getLogs();
            int currentLogCount = currentLogs.size();
            
            int sessionCount;
            synchronized (sessionLock) {
                sessionCount = sessions.size();
            }
            logger.debug("Broadcasting logs - Current count: {}, Last count: {}, Sessions: {}", 
                        currentLogCount, lastLogCount, sessionCount);
            
            // Only send new logs
            if (currentLogCount > lastLogCount) {
                var newLogs = currentLogs.subList(lastLogCount, currentLogCount);
                lastLogCount = currentLogCount;
                
                logger.debug("Sending {} new logs to {} sessions", newLogs.size(), sessionCount);
                
                var message = Map.of(
                    "type", "new_logs",
                    "logs", newLogs,
                    "timestamp", System.currentTimeMillis()
                );
                
                String jsonMessage = objectMapper.writeValueAsString(message);
                TextMessage textMessage = new TextMessage(jsonMessage);
                
                // Broadcast to all connected sessions with synchronization
                synchronized (sessionLock) {
                    List<WebSocketSession> sessionsToRemove = new ArrayList<>();
                    sessions.values().forEach(session -> {
                        try {
                            if (session.isOpen()) {
                                session.sendMessage(textMessage);
                            } else {
                                sessionsToRemove.add(session);
                            }
                        } catch (Exception e) {
                            logger.warn("Error sending message to session: {} - {}", session.getId(), e.getMessage());
                            sessionsToRemove.add(session);
                        }
                    });
                    
                    // Remove closed sessions
                    sessionsToRemove.forEach(session -> {
                        try {
                            if (session.isOpen()) {
                                session.close();
                            }
                        } catch (Exception e) {
                            logger.debug("Error closing session: {}", session.getId(), e);
                        }
                        sessions.remove(session.getId());
                    });
                }
            }
        } catch (Exception e) {
            logger.error("Error broadcasting logs", e);
        }
    }
    
    private void sendStatus(WebSocketSession session) {
        try {
            if (!session.isOpen()) {
                logger.debug("Session {} is not open, skipping status send", session.getId());
                return;
            }
            
            var status = Map.of(
                "type", "status",
                "isRunning", conpotService.isRunning(),
                "logCount", conpotService.getLogs().size(),
                "timestamp", System.currentTimeMillis()
            );
            
            String jsonMessage = objectMapper.writeValueAsString(status);
            session.sendMessage(new TextMessage(jsonMessage));
        } catch (Exception e) {
            logger.warn("Error sending status to session: {} - {}", session.getId(), e.getMessage());
        }
    }
    
    private void sendAllLogs(WebSocketSession session) {
        try {
            if (!session.isOpen()) {
                logger.debug("Session {} is not open, skipping logs send", session.getId());
                return;
            }
            
            var logs = conpotService.getLogs();
            var message = Map.of(
                "type", "all_logs",
                "logs", logs,
                "count", logs.size(),
                "timestamp", System.currentTimeMillis()
            );
            
            String jsonMessage = objectMapper.writeValueAsString(message);
            session.sendMessage(new TextMessage(jsonMessage));
        } catch (Exception e) {
            logger.warn("Error sending all logs to session: {} - {}", session.getId(), e.getMessage());
        }
    }
    
    @EventListener
    public void handleConpotStatusEvent(ConpotStatusEvent event) {
        long currentTime = System.currentTimeMillis();
        if (currentTime - lastStatusUpdate > STATUS_UPDATE_THROTTLE) {
            lastStatusUpdate = currentTime;
            broadcastStatus();
        }
    }
    
    public void broadcastStatus() {
        try {
            var status = Map.of(
                "type", "status_update",
                "isRunning", conpotService.isRunning(),
                "logCount", conpotService.getLogs().size(),
                "timestamp", System.currentTimeMillis()
            );
            
            String jsonMessage = objectMapper.writeValueAsString(status);
            TextMessage textMessage = new TextMessage(jsonMessage);
            
            synchronized (sessionLock) {
                List<WebSocketSession> sessionsToRemove = new ArrayList<>();
                sessions.values().forEach(session -> {
                    try {
                        if (session.isOpen()) {
                            session.sendMessage(textMessage);
                        } else {
                            sessionsToRemove.add(session);
                        }
                    } catch (Exception e) {
                        logger.warn("Error sending status update to session: {} - {}", session.getId(), e.getMessage());
                        sessionsToRemove.add(session);
                    }
                });
                
                // Remove closed sessions
                sessionsToRemove.forEach(session -> {
                    try {
                        if (session.isOpen()) {
                            session.close();
                        }
                    } catch (Exception e) {
                        logger.debug("Error closing session: {}", session.getId(), e);
                    }
                    sessions.remove(session.getId());
                });
            }
        } catch (Exception e) {
            logger.error("Error broadcasting status", e);
        }
    }
    
    private void cleanupDeadSessions() {
        synchronized (sessionLock) {
            List<WebSocketSession> sessionsToRemove = new ArrayList<>();
            sessions.values().forEach(session -> {
                try {
                    if (!session.isOpen()) {
                        sessionsToRemove.add(session);
                    }
                } catch (Exception e) {
                    logger.debug("Error checking session status: {}", session.getId(), e);
                    sessionsToRemove.add(session);
                }
            });
            
            sessionsToRemove.forEach(session -> {
                try {
                    session.close();
                } catch (Exception e) {
                    logger.debug("Error closing dead session: {}", session.getId(), e);
                }
                sessions.remove(session.getId());
            });
            
            if (!sessionsToRemove.isEmpty()) {
                logger.info("Cleaned up {} dead WebSocket sessions", sessionsToRemove.size());
            }
        }
    }
    
    private void sendHeartbeat() {
        synchronized (sessionLock) {
            if (sessions.isEmpty()) {
                return;
            }
            
            try {
                var heartbeat = Map.of(
                    "type", "heartbeat",
                    "timestamp", System.currentTimeMillis()
                );
                
                String jsonMessage = objectMapper.writeValueAsString(heartbeat);
                TextMessage textMessage = new TextMessage(jsonMessage);
                
                List<WebSocketSession> sessionsToRemove = new ArrayList<>();
                sessions.values().forEach(session -> {
                    try {
                        if (session.isOpen()) {
                            session.sendMessage(textMessage);
                        } else {
                            sessionsToRemove.add(session);
                        }
                    } catch (Exception e) {
                        logger.debug("Error sending heartbeat to session: {} - {}", session.getId(), e.getMessage());
                        sessionsToRemove.add(session);
                    }
                });
                
                // Remove dead sessions
                sessionsToRemove.forEach(session -> {
                    try {
                        session.close();
                    } catch (Exception e) {
                        logger.debug("Error closing session after heartbeat: {}", session.getId(), e);
                    }
                    sessions.remove(session.getId());
                });
            } catch (Exception e) {
                logger.debug("Error sending heartbeat: {}", e.getMessage());
            }
        }
    }
} 