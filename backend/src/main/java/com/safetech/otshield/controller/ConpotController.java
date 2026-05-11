package com.safetech.otshield.controller;

import com.safetech.otshield.service.ConpotService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/conpot")
@CrossOrigin(origins = {"http://localhost:3000", "http://127.0.0.1:3000"})
public class ConpotController {
    
    private static final Logger logger = LoggerFactory.getLogger(ConpotController.class);
    
    @Autowired
    private ConpotService conpotService;
    
    @PostMapping("/start")
    public ResponseEntity<Map<String, Object>> startConpot() {
        logger.info("Starting Conpot honeypot");
        Map<String, Object> response = new HashMap<>();
        
        try {
            boolean success = conpotService.startConpot();
            response.put("success", success);
            String message;
            if (success) {
                message = "Conpot started successfully";
            } else {
                message = conpotService.getLastStartError() != null ? conpotService.getLastStartError() : "Failed to start Conpot";
            }
            response.put("message", message);
            response.put("isRunning", conpotService.isRunning());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error starting Conpot", e);
            response.put("success", false);
            response.put("message", "Error starting Conpot: " + e.getMessage());
            return ResponseEntity.internalServerError().body(response);
        }
    }
    
    @PostMapping("/stop")
    public ResponseEntity<Map<String, Object>> stopConpot() {
        logger.info("Stopping Conpot honeypot");
        Map<String, Object> response = new HashMap<>();
        
        try {
            boolean success = conpotService.stopConpot();
            response.put("success", success);
            response.put("message", success ? "Conpot stopped successfully" : "Failed to stop Conpot");
            response.put("isRunning", conpotService.isRunning());
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error stopping Conpot", e);
            response.put("success", false);
            response.put("message", "Error stopping Conpot: " + e.getMessage());
            return ResponseEntity.internalServerError().body(response);
        }
    }
    
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> getStatus() {
        Map<String, Object> response = new HashMap<>();
        response.put("isRunning", conpotService.isRunning());
        response.put("remoteMode", conpotService.isRemoteMode());
        response.put("runtime", conpotService.getRuntime());
        return ResponseEntity.ok(response);
    }
    
    @GetMapping("/logs")
    public ResponseEntity<Map<String, Object>> getLogs() {
        Map<String, Object> response = new HashMap<>();
        List<String> logs = conpotService.getLogs();
        response.put("logs", logs);
        response.put("count", logs.size());
        return ResponseEntity.ok(response);
    }
    
    @DeleteMapping("/logs")
    public ResponseEntity<Map<String, Object>> clearLogs() {
        logger.info("Clearing Conpot logs");
        Map<String, Object> response = new HashMap<>();
        
        try {
            conpotService.clearLogs();
            response.put("success", true);
            response.put("message", "Logs cleared successfully");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("Error clearing logs", e);
            response.put("success", false);
            response.put("message", "Error clearing logs: " + e.getMessage());
            return ResponseEntity.internalServerError().body(response);
        }
    }
    
    @GetMapping("/statistics")
    public ResponseEntity<Map<String, Object>> getStatistics() {
        Map<String, Object> stats = conpotService.getStatistics();
        return ResponseEntity.ok(stats);
    }
    
    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> healthCheck() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "healthy");
        response.put("service", "Conpot");
        response.put("isRunning", conpotService.isRunning());
        return ResponseEntity.ok(response);
    }
} 