package com.safetech.otshield.controller;

import com.safetech.otshield.model.NetworkInterfaceInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/pcap")
public class PcapController {

    private static final Logger logger = LoggerFactory.getLogger(PcapController.class);

    @GetMapping("/health")
    public ResponseEntity<String> healthCheck() {
        logger.info("Health check endpoint called");
        return ResponseEntity.ok("PCAP Controller is running");
    }

    @GetMapping("/websocket-health")
    public ResponseEntity<Map<String, Object>> websocketHealthCheck() {
        logger.info("WebSocket health check endpoint called");
        Map<String, Object> response = new HashMap<>();
        response.put("status", "WebSocket endpoint is available");
        response.put("endpoint", "/ws/livepackets");
        response.put("timestamp", new java.util.Date());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/pcap-interfaces")
    public ResponseEntity<Map<String, Object>> getPcapInterfaces() {
        logger.info("PCAP4J interfaces check endpoint called");
        Map<String, Object> response = new HashMap<>();
        
        try {
            List<org.pcap4j.core.PcapNetworkInterface> pcapInterfaces = org.pcap4j.core.Pcaps.findAllDevs();
            List<Map<String, String>> interfaceList = new ArrayList<>();
            
            for (org.pcap4j.core.PcapNetworkInterface pcapInt : pcapInterfaces) {
                Map<String, String> iface = new HashMap<>();
                iface.put("name", pcapInt.getName());
                iface.put("description", pcapInt.getDescription());
                interfaceList.add(iface);
            }
            
            response.put("status", "PCAP4J interfaces found");
            response.put("count", pcapInterfaces.size());
            response.put("interfaces", interfaceList);
            response.put("nativeLibrary", "available");
        } catch (UnsatisfiedLinkError e) {
            response.put("status", "PCAP4J native library not available");
            response.put("error", e.getMessage());
            response.put("nativeLibrary", "unavailable");
        } catch (Exception e) {
            response.put("status", "Error getting PCAP4J interfaces");
            response.put("error", e.getMessage());
            response.put("nativeLibrary", "error");
        }
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/interfaces")
    public ResponseEntity<List<NetworkInterfaceInfo>> getNetworkInterfaces() {
        logger.info("Fetching network interfaces...");
        try {
            List<NetworkInterfaceInfo> interfaces = new ArrayList<>();
            
            // Check if PCAP4J is available before trying to use it
            boolean pcap4jAvailable = false;
            try {
                // Test PCAP4J availability without triggering ExceptionInInitializerError
                Class.forName("org.pcap4j.core.Pcaps");
                pcap4jAvailable = true;
            } catch (ExceptionInInitializerError | UnsatisfiedLinkError | ClassNotFoundException e) {
                logger.warn("PCAP4J not available, will use Java NetworkInterface fallback: {}", e.getMessage());
                pcap4jAvailable = false;
            }
            
            if (pcap4jAvailable) {
                try {
                    List<org.pcap4j.core.PcapNetworkInterface> pcapInterfaces = org.pcap4j.core.Pcaps.findAllDevs();
                    logger.info("Found {} PCAP4J network interfaces", pcapInterfaces.size());
                    
                    for (org.pcap4j.core.PcapNetworkInterface pcapInt : pcapInterfaces) {
                        logger.info("PCAP4J interface: {} (description: {})", pcapInt.getName(), pcapInt.getDescription());
                        
                        NetworkInterfaceInfo info = new NetworkInterfaceInfo();
                        info.setName(pcapInt.getName());
                        info.setDescription(pcapInt.getDescription());
                        
                        List<String> addresses = new ArrayList<>();
                        pcapInt.getLinkLayerAddresses().forEach(addr -> 
                            addresses.add(addr.toString())
                        );
                        info.setAddresses(addresses);
                        
                        interfaces.add(info);
                        logger.info("Added PCAP4J interface: {} with {} addresses", pcapInt.getName(), addresses.size());
                    }
                } catch (Exception e) {
                    logger.warn("PCAP4J failed, falling back to Java NetworkInterface: {}", e.getMessage());
                    pcap4jAvailable = false;
                }
            }
            
            // Fallback to Java NetworkInterface if PCAP4J is not available or failed
            if (!pcap4jAvailable || interfaces.isEmpty()) {
                logger.info("Using Java NetworkInterface fallback");
                List<NetworkInterface> allInterfaces = Collections.list(NetworkInterface.getNetworkInterfaces());
                logger.info("Found {} total Java network interfaces", allInterfaces.size());
                
                for (NetworkInterface netInt : allInterfaces) {
                    logger.info("Checking Java interface: {} (display: {}) - loopback: {}, up: {}", 
                        netInt.getName(), netInt.getDisplayName(), netInt.isLoopback(), netInt.isUp());
                    
                    if (netInt.isUp()) {
                        NetworkInterfaceInfo info = new NetworkInterfaceInfo();
                        info.setName(netInt.getName());
                        info.setDescription(netInt.getDisplayName());
                        
                        List<String> addresses = new ArrayList<>();
                        netInt.getInterfaceAddresses().forEach(addr -> 
                            addresses.add(addr.getAddress().getHostAddress())
                        );
                        info.setAddresses(addresses);
                        
                        interfaces.add(info);
                        logger.info("Added Java interface: {} with {} addresses", netInt.getName(), addresses.size());
                    } else {
                        logger.info("Skipping Java interface: {} - not up", netInt.getName());
                    }
                }
            }
            
            logger.info("Returning {} available network interfaces", interfaces.size());
            return ResponseEntity.ok(interfaces);
        } catch (SocketException e) {
            logger.error("Error fetching network interfaces: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(Collections.emptyList());
        } catch (Exception e) {
            logger.error("Unexpected error fetching network interfaces: {}", e.getMessage(), e);
            return ResponseEntity.status(500).body(Collections.emptyList());
        }
    }
} 