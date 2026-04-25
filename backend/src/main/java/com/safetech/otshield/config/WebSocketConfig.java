package com.safetech.otshield.config;

import com.safetech.otshield.websocket.LivePacketHandler;
import com.safetech.otshield.websocket.ConpotLogWebSocketHandler;
import com.safetech.otshield.websocket.DecoyStreamHandler;
import com.safetech.otshield.websocket.FakeHmiStreamHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.socket.config.annotation.EnableWebSocket;
import org.springframework.web.socket.config.annotation.WebSocketConfigurer;
import org.springframework.web.socket.config.annotation.WebSocketHandlerRegistry;
import org.springframework.web.socket.server.standard.ServletServerContainerFactoryBean;
import org.springframework.context.annotation.Bean;

@Configuration
@EnableWebSocket
public class WebSocketConfig implements WebSocketConfigurer {

    private final LivePacketHandler livePacketHandler;
    private final ConpotLogWebSocketHandler conpotLogWebSocketHandler;
    private final DecoyStreamHandler decoyStreamHandler;
    private final FakeHmiStreamHandler fakeHmiStreamHandler;

    public WebSocketConfig(LivePacketHandler livePacketHandler,
                           ConpotLogWebSocketHandler conpotLogWebSocketHandler,
                           DecoyStreamHandler decoyStreamHandler,
                           FakeHmiStreamHandler fakeHmiStreamHandler) {
        this.livePacketHandler = livePacketHandler;
        this.conpotLogWebSocketHandler = conpotLogWebSocketHandler;
        this.decoyStreamHandler = decoyStreamHandler;
        this.fakeHmiStreamHandler = fakeHmiStreamHandler;
    }

    @Override
    public void registerWebSocketHandlers(WebSocketHandlerRegistry registry) {
        // Endpoint for live packet data. Configure allowed origins for development and production.
        registry.addHandler(livePacketHandler, "/ws/livepackets")
                .setAllowedOrigins("http://localhost:3000", "http://127.0.0.1:3000");

        // Endpoint for Conpot logs
        registry.addHandler(conpotLogWebSocketHandler, "/ws/conpot-logs")
                .setAllowedOrigins("http://localhost:3000", "http://127.0.0.1:3000");

        // Endpoint for Decoy Layer live engagement stream
        registry.addHandler(decoyStreamHandler, "/ws/decoy/stream")
                .setAllowedOrigins("http://localhost:3000", "http://127.0.0.1:3000");

        // Endpoint for Fake HMI live telemetry + interactions
        registry.addHandler(fakeHmiStreamHandler, "/ws/deception/hmi-stream")
                .setAllowedOrigins("http://localhost:3000", "http://127.0.0.1:3000");
    }
    
    @Bean
    public ServletServerContainerFactoryBean createWebSocketContainer() {
        ServletServerContainerFactoryBean container = new ServletServerContainerFactoryBean();
        container.setMaxTextMessageBufferSize(65536);
        container.setMaxBinaryMessageBufferSize(65536);
        container.setMaxSessionIdleTimeout(300000L); // 5 minutes
        container.setAsyncSendTimeout(30000L); // 30 seconds
        return container;
    }
} 