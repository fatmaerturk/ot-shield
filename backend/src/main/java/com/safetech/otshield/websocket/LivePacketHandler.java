package com.safetech.otshield.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.socket.CloseStatus;
import org.springframework.web.socket.TextMessage;
import org.springframework.web.socket.WebSocketSession;
import org.springframework.web.socket.handler.TextWebSocketHandler;
import com.safetech.otshield.service.PcapAnalysisService;
import com.fasterxml.jackson.core.type.TypeReference;
import java.util.Map;

import java.io.IOException;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import java.util.Map;

@Component
public class LivePacketHandler extends TextWebSocketHandler {

    private static final Logger logger = LoggerFactory.getLogger(LivePacketHandler.class);
    private final CopyOnWriteArrayList<WebSocketSession> sessions = new CopyOnWriteArrayList<>();
    private final ObjectMapper objectMapper = new ObjectMapper()
        .registerModule(new JavaTimeModule())
        .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS); // For converting packets to JSON with JavaTime support
    private PcapAnalysisService pcapAnalysisService; // Inject service for live capture
    
    // Heartbeat scheduler for connection health monitoring
    private final ScheduledExecutorService heartbeatScheduler = Executors.newScheduledThreadPool(1);

    // Setter injection of PcapAnalysisService to break circular dependency
    @Autowired
    public void setPcapAnalysisService(@Lazy PcapAnalysisService pcapAnalysisService) {
        this.pcapAnalysisService = pcapAnalysisService;
    }

    @Override
    public void afterConnectionEstablished(WebSocketSession session) throws Exception {
        sessions.add(session);
        logger.info("WebSocket connection established: Session ID = {}, Total sessions = {}", session.getId(), sessions.size());
        
        // Send initial connection confirmation
        try {
            String welcomeMessage = objectMapper.writeValueAsString(Map.of(
                "type", "connection",
                "status", "established",
                "sessionId", session.getId()
            ));
            session.sendMessage(new TextMessage(welcomeMessage));
        } catch (Exception e) {
            logger.warn("Could not send welcome message to session {}: {}", session.getId(), e.getMessage());
        }
    }

    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {
        String payload = message.getPayload();
        logger.debug("Received WebSocket message from {}: {}", session.getId(), payload);
        
        // Handle start/stop commands from frontend
        try {
            Map<String, String> command = objectMapper.readValue(payload, new TypeReference<Map<String, String>>() {});
            String action = command.get("action");
            if ("start".equalsIgnoreCase(action)) {
                String iface = command.get("interfaceName");
                logger.info("Request received to start capture on interface: {}", iface);
                try {
                    pcapAnalysisService.startLiveCapture(iface);
                    
                    // Send success confirmation
                    String successMessage = objectMapper.writeValueAsString(Map.of(
                        "type", "capture",
                        "status", "started",
                        "interface", iface
                    ));
                    session.sendMessage(new TextMessage(successMessage));
                } catch (UnsatisfiedLinkError e) {
                    logger.error("PCAP4J native library not available for live capture: {}", e.getMessage());
                    // Send error message to client
                    String errorMessage = objectMapper.writeValueAsString(Map.of(
                        "type", "error",
                        "error", "PCAP4J native library not available",
                        "message", "Live capture requires Npcap to be installed. Please download and install Npcap from https://npcap.com/ and restart the application."
                    ));
                    session.sendMessage(new TextMessage(errorMessage));
                } catch (Exception e) {
                    logger.error("Error starting live capture: {}", e.getMessage(), e);
                    // Send error message to client
                    String errorMessage = objectMapper.writeValueAsString(Map.of(
                        "type", "error",
                        "error", "Failed to start live capture",
                        "message", e.getMessage()
                    ));
                    session.sendMessage(new TextMessage(errorMessage));
                }
            } else if ("stop".equalsIgnoreCase(action)) {
                logger.info("Request received to stop capture");
                try {
                    pcapAnalysisService.stopLiveCapture();
                    
                    // Send success confirmation
                    String successMessage = objectMapper.writeValueAsString(Map.of(
                        "type", "capture",
                        "status", "stopped"
                    ));
                    session.sendMessage(new TextMessage(successMessage));
                } catch (Exception e) {
                    logger.error("Error stopping live capture: {}", e.getMessage(), e);
                    
                    // Send error message to client
                    String errorMessage = objectMapper.writeValueAsString(Map.of(
                        "type", "error",
                        "error", "Failed to stop live capture",
                        "message", e.getMessage()
                    ));
                    session.sendMessage(new TextMessage(errorMessage));
                }
            } else if ("ping".equalsIgnoreCase(action)) {
                // Handle heartbeat ping
                try {
                    String pongMessage = objectMapper.writeValueAsString(Map.of(
                        "type", "pong",
                        "timestamp", System.currentTimeMillis()
                    ));
                    session.sendMessage(new TextMessage(pongMessage));
                } catch (Exception e) {
                    logger.warn("Could not send pong to session {}: {}", session.getId(), e.getMessage());
                }
            }
        } catch (Exception e) {
            logger.error("Error processing WebSocket message: {}", payload, e);
            // Send error message to client
            try {
                String errorMessage = objectMapper.writeValueAsString(Map.of(
                    "type", "error",
                    "error", "Invalid message format",
                    "message", "Failed to parse WebSocket message"
                ));
                session.sendMessage(new TextMessage(errorMessage));
            } catch (Exception sendError) {
                logger.error("Error sending error message to client: {}", sendError.getMessage());
            }
        }
    }

    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) throws Exception {
        sessions.remove(session);
        logger.info("WebSocket connection closed: Session ID = {}, Status = {}, Total sessions = {}", session.getId(), status, sessions.size());
    }

    @Override
    public void handleTransportError(WebSocketSession session, Throwable exception) throws Exception {
        logger.error("WebSocket transport error for Session ID = {}: {}", session.getId(), exception.getMessage());
        
        // Log the full stack trace for debugging
        if (logger.isDebugEnabled()) {
            logger.debug("Full transport error stack trace:", exception);
        }
        
        // Try to close the session gracefully
        try {
            if (session.isOpen()) {
                session.close(CloseStatus.SERVER_ERROR);
            }
        } catch (Exception closeError) {
            logger.warn("Error closing session {} after transport error: {}", session.getId(), closeError.getMessage());
        }
        
        // Remove the session from our list
        sessions.remove(session);
    }

    /**
     * Sends packet data (as a JSON string) to all connected WebSocket clients.
     * @param packetDataJson The packet data serialized as a JSON string.
     */
    public void broadcastPacketData(String packetDataJson) {
        TextMessage message = new TextMessage(packetDataJson);
        sessions.removeIf(session -> {
            try {
                if (session.isOpen()) {
                    session.sendMessage(message);
                    return false; // Keep the session
                } else {
                    logger.debug("Removing closed session: {}", session.getId());
                    return true; // Remove the session
                }
            } catch (IOException e) {
                logger.warn("Error sending packet data to WebSocket Session ID = {}: {}", session.getId(), e.getMessage());
                return true; // Remove the session
            } catch (Exception e) {
                logger.error("Unexpected error sending packet data to WebSocket Session ID = {}: {}", session.getId(), e.getMessage());
                return true; // Remove the session
            }
        });
    }

    // Overload for broadcasting any object (will be converted to JSON)
    public void broadcastPacketData(Object packetData) {
        try {
            String json = objectMapper.writeValueAsString(packetData);
            broadcastPacketData(json);
        } catch (IOException e) {
            logger.error("Error serializing packet data object to JSON", e);
        } catch (Exception e) {
            logger.error("Unexpected error serializing packet data object to JSON", e);
        }
    }

    public int getSessionCount() {
        return sessions.size();
    }
    
    /**
     * Cleanup method to be called when the application shuts down
     */
    public void cleanup() {
        logger.info("Cleaning up WebSocket handler...");
        
        // Shutdown heartbeat scheduler
        if (heartbeatScheduler != null && !heartbeatScheduler.isShutdown()) {
            heartbeatScheduler.shutdown();
            try {
                if (!heartbeatScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                    heartbeatScheduler.shutdownNow();
                }
            } catch (InterruptedException e) {
                heartbeatScheduler.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        
        // Close all sessions
        for (WebSocketSession session : sessions) {
            try {
                if (session.isOpen()) {
                    session.close(CloseStatus.GOING_AWAY);
                }
            } catch (Exception e) {
                logger.warn("Error closing session {} during cleanup: {}", session.getId(), e.getMessage());
            }
        }
        sessions.clear();
        
        logger.info("WebSocket handler cleanup completed");
    }
} 