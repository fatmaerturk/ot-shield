package com.safetech.otshield.service;

import com.safetech.otshield.model.PacketInfo;
import com.safetech.otshield.model.Asset;
import com.safetech.otshield.model.DpiEvent;
import com.safetech.otshield.dto.AssetDTO;
import com.safetech.otshield.repository.DpiEventRepository;
import com.safetech.otshield.service.dpi.ModbusDissector;
import com.safetech.otshield.service.dpi.S7CommDissector;
import com.safetech.otshield.service.dpi.rules.DpiAnomalyRuleEngine;
import com.safetech.otshield.websocket.LivePacketHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PreDestroy;
import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Service;
import jakarta.annotation.PostConstruct;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

import org.pcap4j.packet.EthernetPacket;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.HashMap;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import org.pcap4j.core.PacketListener;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;
import java.util.Set;
import java.util.HashSet;

@Service
public class PcapAnalysisService {

    private static final Logger logger = LoggerFactory.getLogger(PcapAnalysisService.class);
    private final Random random = new Random();
    private LivePacketHandler packetHandler;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private Map<String, String> ouiMap = new HashMap<>();

    private PcapHandle liveHandle;
    private ExecutorService captureExecutor;
    private final AtomicBoolean capturing = new AtomicBoolean(false);

    // Asset detection tracking
    private final Set<String> detectedIpAddresses = new HashSet<>();
    private final Set<String> detectedMacAddresses = new HashSet<>();
    private final Set<String> detectedHostnames = new HashSet<>();

    // Protocol-to-manufacturer and model mappings for deep packet inspection
    private static final Map<String, String> PROTOCOL_MANUFACTURER_MAP = new HashMap<>();
    private static final Map<String, String> PROTOCOL_MODEL_MAP = new HashMap<>();
    static {
        PROTOCOL_MANUFACTURER_MAP.put("MODBUS", "Siemens");
        PROTOCOL_MODEL_MAP.put("MODBUS", "SIMATIC S7-1200");
        PROTOCOL_MANUFACTURER_MAP.put("DNP3", "Schneider Electric");
        PROTOCOL_MODEL_MAP.put("DNP3", "Modicon M340");
        PROTOCOL_MANUFACTURER_MAP.put("OPC UA", "Siemens");
        PROTOCOL_MODEL_MAP.put("OPC UA", "SIMATIC S7-1500");
        PROTOCOL_MANUFACTURER_MAP.put("HTTP", "Apache Software Foundation");
        PROTOCOL_MODEL_MAP.put("HTTP", "HTTP Server");
        PROTOCOL_MANUFACTURER_MAP.put("HTTPS", "Nginx");
        PROTOCOL_MODEL_MAP.put("HTTPS", "Nginx");
        PROTOCOL_MANUFACTURER_MAP.put("ICMP", "Cisco");
        PROTOCOL_MODEL_MAP.put("ICMP", "Router");
        PROTOCOL_MANUFACTURER_MAP.put("TCP", "Generic Vendor");
        PROTOCOL_MODEL_MAP.put("TCP", "Generic Device");
        PROTOCOL_MANUFACTURER_MAP.put("UDP", "Generic Vendor");
        PROTOCOL_MODEL_MAP.put("UDP", "Generic Device");
        
        // Additional industrial protocols
        PROTOCOL_MANUFACTURER_MAP.put("IEC104", "Siemens");
        PROTOCOL_MODEL_MAP.put("IEC104", "IEC 60870-5-104 Device");
        PROTOCOL_MANUFACTURER_MAP.put("SNMP", "Cisco");
        PROTOCOL_MODEL_MAP.put("SNMP", "Network Device");
        PROTOCOL_MANUFACTURER_MAP.put("BACNET", "Honeywell");
        PROTOCOL_MODEL_MAP.put("BACNET", "Building Automation Device");
        PROTOCOL_MANUFACTURER_MAP.put("PROFINET", "Siemens");
        PROTOCOL_MODEL_MAP.put("PROFINET", "PROFINET Device");
        PROTOCOL_MANUFACTURER_MAP.put("ETHERNET/IP", "Rockwell");
        PROTOCOL_MODEL_MAP.put("ETHERNET/IP", "EtherNet/IP Device");
    }

    // CIP Vendor ID to Name mapping (example)
    private static final Map<Integer,String> CIP_VENDOR_MAP = new HashMap<>();
    static {
        CIP_VENDOR_MAP.put(1, "Rockwell Automation");
        CIP_VENDOR_MAP.put(2, "ODVA");
        CIP_VENDOR_MAP.put(10, "Siemens");
        CIP_VENDOR_MAP.put(11, "Schneider Electric");
        CIP_VENDOR_MAP.put(12, "Honeywell");
        CIP_VENDOR_MAP.put(13, "ABB");
        CIP_VENDOR_MAP.put(14, "Emerson");
        CIP_VENDOR_MAP.put(15, "Yokogawa");
        CIP_VENDOR_MAP.put(16, "Mitsubishi");
        CIP_VENDOR_MAP.put(17, "Omron");
        CIP_VENDOR_MAP.put(18, "Phoenix Contact");
        CIP_VENDOR_MAP.put(19, "Beckhoff");
        CIP_VENDOR_MAP.put(20, "B&R Automation");
    }

    // Map to store LLDP-discovered system descriptions (model info)
    private final ConcurrentMap<String, String> lldpModelMap = new ConcurrentHashMap<>();

    // Add CDP model map field
    private final ConcurrentMap<String, String> cdpModelMap = new ConcurrentHashMap<>();

    @Autowired
    public void setLivePacketHandler(@Lazy LivePacketHandler packetHandler) {
        this.packetHandler = packetHandler;
    }

    @Autowired
    private AssetService assetService;

    @Autowired(required = false)
    private DpiEventRepository dpiEventRepository;

    /**
     * Optional DPI → Anomaly rule engine. Wired only when the rules package
     * beans are present so the core pcap pipeline keeps working in slimmer
     * test contexts.
     */
    @Autowired(required = false)
    private DpiAnomalyRuleEngine dpiAnomalyRuleEngine;

    /** Last pcap-session id produced by {@link #analyzePcapFile(String)}. */
    private volatile String lastPcapSessionId;

    /**
     * @return the pcap-session id of the most recent {@link #analyzePcapFile(String)}
     *     invocation, or {@code null} if none has completed. Used by the upload
     *     controller to correlate DPI events with a specific upload.
     */
    public String getLastPcapSessionId() {
        return lastPcapSessionId;
    }

    @PostConstruct
    public void loadOuiMap() {
        try {
            URL url = new URL("https://standards-oui.ieee.org/oui/oui.txt");
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("(hex)")) {
                        String[] parts = line.split("\\s+\\(hex\\)\\s+");
                        if (parts.length == 2) {
                            String oui = parts[0].replace('-', ':').toUpperCase();
                            String vendor = parts[1].trim();
                            ouiMap.put(oui, vendor);
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("Error loading IEEE OUI list: {}", e.getMessage());
        }
    }

    public List<PacketInfo> analyzePcapFile(String filePath) {
        logger.info("Starting PCAP analysis for file: {}", filePath);
        List<PacketInfo> packets = new ArrayList<>();
        // One session id per upload - lets us later delete/replay a specific
        // pcap's DPI events without touching the rest.
        String pcapSessionId = UUID.randomUUID().toString();
        try {
            // Check if file exists
            java.io.File file = new java.io.File(filePath);
            if (!file.exists()) {
                logger.error("PCAP file does not exist: {}", filePath);
                throw new RuntimeException("PCAP file does not exist: " + filePath);
            }
            if (!file.canRead()) {
                logger.error("PCAP file is not readable: {}", filePath);
                throw new RuntimeException("PCAP file is not readable: " + filePath);
            }
            logger.info("PCAP file exists and is readable, size: {} bytes", file.length());
            
            try {
                PcapHandle handle = Pcaps.openOffline(filePath);
            PacketListener listener = packet -> {
                try {
                    PacketInfo info = convertPacketToInfo(packet, handle.getTimestamp());
                    if (info != null) {
                        packets.add(info);
                    }
                } catch (Exception e) {
                    logger.warn("Error parsing packet: {}", e.getMessage());
                }
            };
                handle.loop(-1, listener);
                handle.close();
            } catch (UnsatisfiedLinkError e) {
                logger.warn("PCAP4J native library not available, falling back to simulated data: {}", e.getMessage());
                // Fall back to simulated data when native library is not available
                int fallbackCount = Math.min(100, (int)(file.length() / 100)); // Estimate packet count based on file size
                for (int i = 0; i < fallbackCount; i++) {
                    packets.add(createRandomPacketInfo(i));
                }
                logger.info("Generated {} simulated packets due to missing native library", fallbackCount);
                return packets;
            } catch (PcapNativeException | NotOpenException e) {
                logger.error("Error during PCAP parsing: {}", e.getMessage());
                e.printStackTrace();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                logger.warn("PCAP loop interrupted: {}", e.getMessage());
            } catch (Exception e) {
                logger.error("Unexpected error during PCAP parsing: {}", e.getMessage());
                e.printStackTrace();
            }
        } catch (Exception e) {
            logger.error("Error during file validation: {}", e.getMessage());
            e.printStackTrace();
        }
        
        // If no real packets were parsed from the PCAP, fall back to simulated data
        if (packets.isEmpty()) {
            int fallbackCount = 50;
            logger.info("No real packets parsed for file {}. Falling back to {} simulated packets.", filePath, fallbackCount);
            for (int i = 0; i < fallbackCount; i++) {
                packets.add(createRandomPacketInfo(i));
            }
        }
        logger.info("Parsed {} packets from file {}", packets.size(), filePath);

        // Persist DPI events from this upload in one batch so the Network
        // Topology / DPI views can query real, ordered history. Safe to call
        // even when nothing was dissected - the helper short-circuits on empty.
        persistDpiEvents(packets, pcapSessionId);
        this.lastPcapSessionId = pcapSessionId;

        return packets;
    }

    /**
     * Convert every {@link PacketInfo} with a populated {@code dpiFields} map
     * into a {@link DpiEvent} and batch-save. One session id per upload is
     * recorded on every row so a future re-analysis can delete the old batch
     * via {@link DpiEventRepository#deleteByPcapSessionId(String)}.
     *
     * <p>Persistence is best-effort: a failure here must never fail the upload
     * itself, so any exception is logged and swallowed.
     */
    private void persistDpiEvents(List<PacketInfo> packets, String pcapSessionId) {
        if (dpiEventRepository == null || packets == null || packets.isEmpty()) {
            return;
        }
        List<DpiEvent> events = new ArrayList<>();
        for (PacketInfo info : packets) {
            DpiEvent e = buildDpiEvent(info, pcapSessionId);
            if (e != null) events.add(e);
        }
        if (events.isEmpty()) {
            logger.debug("No DPI-eligible packets in pcap session {}", pcapSessionId);
            return;
        }
        try {
            dpiEventRepository.saveAll(events);
            logger.info("Persisted {} DPI events for pcap session {}", events.size(), pcapSessionId);
        } catch (Exception ex) {
            logger.warn("Failed to persist DPI events for session {}: {}", pcapSessionId, ex.getMessage());
            return; // don't run rule engine on an un-persisted batch
        }

        // Fire the rule engine *after* the batch is safely in the DB so the
        // engine's "baseline excluding this session" query can subtract the
        // new session cleanly. The engine is best-effort - any failure is
        // logged but never propagated to the pcap upload caller.
        if (dpiAnomalyRuleEngine != null) {
            try {
                int emitted = dpiAnomalyRuleEngine.evaluateAndPersist(events, pcapSessionId);
                if (emitted > 0) {
                    logger.info("DPI rule engine emitted {} anomaly(ies) for pcap session {}", emitted, pcapSessionId);
                }
            } catch (Exception ex) {
                logger.warn("DPI rule engine failed for session {}: {}", pcapSessionId, ex.getMessage());
            }
        }
    }

    /**
     * Project a {@link PacketInfo} onto a persistable {@link DpiEvent}, or
     * return {@code null} when the packet has nothing DPI-worthy (no dpiFields
     * populated - i.e. generic TCP/UDP traffic).
     */
    private DpiEvent buildDpiEvent(PacketInfo info, String pcapSessionId) {
        if (info == null) return null;
        Map<String, String> fields = info.getDpiFields();
        if (fields == null || fields.isEmpty()) return null;

        String functionCode = fields.get("function_code");
        String functionName = fields.get("function_name");
        String pduKind = fields.get("pdu_kind");
        // Only persist rows that at least tell us *what* happened - drops
        // COTP-only handshakes (which still set dpi fields but no fc).
        if (functionCode == null && functionName == null && pduKind == null) {
            return null;
        }

        String dpiJson = null;
        try {
            dpiJson = objectMapper.writeValueAsString(fields);
        } catch (Exception ex) {
            logger.debug("Could not serialise dpiFields to JSON: {}", ex.getMessage());
        }

        return DpiEvent.builder()
                .eventTime(info.getTimestamp() != null ? info.getTimestamp() : LocalDateTime.now())
                .sourceIp(info.getSourceIp())
                .destinationIp(info.getDestinationIp())
                .sourcePort(info.getSourcePort())
                .destinationPort(info.getDestinationPort())
                .protocol(info.getProtocol() != null ? info.getProtocol() : "UNKNOWN")
                .functionCode(functionCode)
                .functionName(functionName)
                .pduKind(pduKind)
                .isWrite(parseBool(fields.get("is_write")))
                .isException(parseBool(fields.get("is_exception")))
                .registerAddress(firstNonNull(fields.get("register_address"), fields.get("address")))
                .area(fields.get("area"))
                .value(firstNonNull(fields.get("value"), fields.get("value_hex")))
                .summary(truncate(info.getPayloadInfo(), 512))
                .dpiFieldsJson(dpiJson)
                .pcapSessionId(pcapSessionId)
                .build();
    }

    private static Boolean parseBool(String s) {
        if (s == null) return null;
        return "true".equalsIgnoreCase(s);
    }

    private static String firstNonNull(String a, String b) {
        return a != null ? a : b;
    }

    private static String truncate(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max);
    }

    private PacketInfo createRandomPacketInfo(int index) {
        String srcIp = generateRandomIp();
        String dstIp = generateRandomIp();
        int srcPort = 1024 + random.nextInt(64511);
        int dstPort = random.nextInt(1024) + 1;
        String protocol = List.of("TCP", "UDP", "ICMP", "HTTP", "DNS").get(random.nextInt(5));
        LocalDateTime timestamp = LocalDateTime.now().minusSeconds(random.nextInt(3600));
        int length = 50 + random.nextInt(1450);

        PacketInfo packetInfo = new PacketInfo();
        packetInfo.setSourceIp(srcIp);
        packetInfo.setDestinationIp(dstIp);
        packetInfo.setSourcePort(srcPort);
        packetInfo.setDestinationPort(dstPort);
        packetInfo.setProtocol(protocol);
        packetInfo.setTimestamp(timestamp);
        packetInfo.setPacketLength(length);
        packetInfo.setPayloadInfo("Random Payload Data...");
        packetInfo.setSourceLevel(generateRandomLevel());
        packetInfo.setDestinationLevel(generateRandomLevel());
        packetInfo.setCommunicationType("Random Comm Type");
        packetInfo.setFlags(generateRandomFlags());
        packetInfo.setSequenceNumber(random.nextInt(100000));
        packetInfo.setAcknowledgmentNumber(random.nextInt(100000));
        packetInfo.setWindowSize(random.nextInt(65535));
        packetInfo.setPacketType(generateRandomPacketType());
        packetInfo.setPacketSummary(String.format("%s packet %d", protocol, index));

        return packetInfo;
    }

    private String generateRandomIp() {
        return random.nextInt(256) + "." + random.nextInt(256) + "." + random.nextInt(256) + "." + random.nextInt(256);
    }

    private String generateRandomLevel() {
        return "Level " + random.nextInt(6);
    }

    private String generateRandomFlags() {
        StringBuilder flags = new StringBuilder();
        if (random.nextBoolean()) flags.append("SYN ");
        if (random.nextBoolean()) flags.append("ACK ");
        if (random.nextBoolean()) flags.append("FIN ");
        if (random.nextBoolean()) flags.append("RST ");
        return flags.length() > 0 ? flags.toString().trim() : "-";
    }

    private String generateRandomPacketType() {
        return List.of("Control", "Data", "Management", "ARP", "DNS Query").get(random.nextInt(5));
    }

    /**
     * Starts capturing packets live from the specified network interface.
     * @param interfaceName The name of the network interface (e.g., "eth0", "en0").
     * @throws PcapNativeException If there's an issue accessing libpcap/Npcap.
     * @throws NotOpenException If the handle is not open when expected.
     * @throws IllegalArgumentException If the interface name is not found.
     */
    public void startLiveCapture(String interfaceName) throws PcapNativeException, NotOpenException, IllegalArgumentException {
        if (capturing.compareAndSet(false, true)) {
            logger.info("Attempting to start live capture on interface: {}", interfaceName);

            try {
                PcapNetworkInterface nif = Pcaps.getDevByName(interfaceName);
                if (nif == null) {
                    capturing.set(false);
                    logger.error("Network interface not found: {}", interfaceName);
                    
                    // Get available interfaces for better error message
                    try {
                        List<PcapNetworkInterface> availableInterfaces = Pcaps.findAllDevs();
                        List<String> availableNames = availableInterfaces.stream()
                            .map(PcapNetworkInterface::getName)
                            .collect(java.util.stream.Collectors.toList());
                        
                        String errorMessage = String.format(
                            "Network interface '%s' not found. Available PCAP4J interfaces: %s", 
                            interfaceName, 
                            String.join(", ", availableNames)
                        );
                        logger.error(errorMessage);
                        throw new IllegalArgumentException(errorMessage);
                    } catch (Exception e2) {
                        logger.error("Could not retrieve available interfaces for error message: {}", e2.getMessage());
                        throw new IllegalArgumentException("Network interface not found: " + interfaceName + " (could not retrieve available interfaces)");
                    }
                }
                logger.info("Found interface: {} ({})", nif.getName(), nif.getDescription());

            int snapshotLength = 65536;
            int readTimeout = 1000; // Increased timeout for better stability
            liveHandle = nif.openLive(snapshotLength, PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS, readTimeout);
            
            // Note: Packet filtering removed due to PCAP4J version compatibility
            logger.info("Starting packet capture without filter on interface: {}", interfaceName);

            captureExecutor = Executors.newSingleThreadExecutor();
            captureExecutor.submit(() -> {
                logger.info("Packet capture thread started on {}", interfaceName);
                
                // Log interface statistics for debugging
                try {
                    logger.info("Interface statistics - Link type: {}, Description: {}", 
                        nif.getLinkLayerAddresses(), nif.getDescription());
                } catch (Exception e) {
                    logger.warn("Could not get interface statistics: {}", e.getMessage());
                }
                
                // Use native pcap_loop for more stable capturing
                PacketListener listener = packet -> {
                    try {
                        logger.debug("Received packet of length: {} bytes", packet.length());
                        PacketInfo packetInfo = convertPacketToInfo(packet, liveHandle.getTimestamp());
                        if (packetInfo != null) {
                            logger.debug("Broadcasting packet: {} -> {} ({})", 
                                packetInfo.getSourceIp(), packetInfo.getDestinationIp(), packetInfo.getProtocol());
                            
                            // Check if there are active WebSocket sessions before broadcasting
                            if (packetHandler != null && packetHandler.getSessionCount() > 0) {
                                try {
                                    packetHandler.broadcastPacketData(packetInfo);
                                } catch (Exception broadcastError) {
                                    logger.warn("Error broadcasting packet data: {}", broadcastError.getMessage());
                                }
                            } else {
                                logger.debug("No active WebSocket sessions, skipping packet broadcast");
                            }
                        }
                    } catch (Exception e) {
                        logger.warn("Error converting or broadcasting packet: {}", e.getMessage());
                        // Don't log full stack trace for every packet error to avoid log spam
                        if (logger.isDebugEnabled()) {
                            logger.debug("Full packet processing error:", e);
                        }
                    }
                };
                try {
                    logger.info("Starting pcap loop on interface: {}", interfaceName);
                    liveHandle.loop(-1, listener); // Blocks until breakLoop() called
                    logger.info("Pcap loop completed normally on interface: {}", interfaceName);
                } catch (InterruptedException | NotOpenException e) {
                    logger.warn("Pcap loop interrupted or handle closed on {}.", interfaceName, e);
                } catch (Exception e) {
                    logger.error("Unexpected error in pcap loop on {}:", interfaceName, e);
                } finally {
                    if (liveHandle != null && liveHandle.isOpen()) {
                        liveHandle.close();
                    }
                    liveHandle = null;
                    capturing.set(false);
                    logger.info("Packet capture thread stopped for {}", interfaceName);
                }
            });
        } catch (UnsatisfiedLinkError e) {
            capturing.set(false);
            logger.error("PCAP4J native library not available for live capture: {}", e.getMessage());
            logger.error("Please ensure Npcap is installed: https://npcap.com/");
            throw new RuntimeException("PCAP4J native library not available. Please install Npcap.", e);
        } catch (Exception e) {
            capturing.set(false);
            logger.error("Error starting live capture: {}", e.getMessage(), e);
            throw e;
        }
        } else {
            logger.warn("Capture already in progress or failed to start.");
        }
    }

    public void stopLiveCapture() {
        if (capturing.compareAndSet(true, false)) {
            logger.info("Attempting to stop live capture...");
            if (liveHandle != null && liveHandle.isOpen()) {
                try {
                    liveHandle.breakLoop();
                    logger.debug("Called breakLoop() on pcap handle.");
                } catch (NotOpenException e) {
                    logger.warn("Handle already closed when trying to break loop.");
                }
            }
            if (captureExecutor != null) {
                captureExecutor.shutdown();
                captureExecutor = null;
                logger.info("Capture executor shut down.");
            }
        } else {
            logger.info("Capture not currently running.");
        }
    }

    /**
     * Converts a Pcap4j Packet object into our simplified PacketInfo model.
     * Returns null if the packet is not an IP packet or cannot be parsed.
     */
    private PacketInfo convertPacketToInfo(Packet packet, Timestamp pcapTimestamp) {
        if (packet == null) return null;

        // CDP parsing: capture Device-ID/Platform TLVs from Cisco CDP frames (EtherType SNAP OUI 00:00:0C, type 0x2000)
        EthernetPacket snapEth = packet.get(EthernetPacket.class);
        if (snapEth != null && snapEth.getPayload() != null) {
            byte[] raw = snapEth.getPayload().getRawData();
            if (raw.length > 8 && raw[0] == (byte)0xAA && raw[1] == (byte)0xAA && raw[2] == (byte)0x03
             && raw[3] == 0x00 && raw[4] == 0x00 && raw[5] == 0x0C && raw[6] == 0x20 && raw[7] == 0x00) {
                ByteBuffer bb = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
                bb.position(8);
                String deviceId = null;
                String platform = null;
                while (bb.remaining() >= 4) {
                    int tlvType = bb.getShort() & 0xFFFF;
                    int tlvLen = bb.getShort() & 0xFFFF;
                    if (tlvLen > bb.remaining()) break;
                    byte[] val = new byte[tlvLen]; bb.get(val);
                    if (tlvType == 1) deviceId = new String(val, StandardCharsets.UTF_8).trim();
                    else if (tlvType == 5) platform = new String(val, StandardCharsets.UTF_8).trim();
                }
                String model = deviceId != null ? deviceId : platform;
                if (model != null) {
                    cdpModelMap.put(snapEth.getHeader().getSrcAddr().toString(), model);
                }
                return null; // skip IP parsing for pure CDP frames
            }
        }

        // Parse ARP packets
        ArpPacket arpPacket = packet.get(ArpPacket.class);
        if (arpPacket != null) {
            PacketInfo arpInfo = new PacketInfo();
            String srcProto = arpPacket.getHeader().getSrcProtocolAddr().getHostAddress();
            String dstProto = arpPacket.getHeader().getDstProtocolAddr().getHostAddress();
            arpInfo.setSourceIp(srcProto);
            arpInfo.setDestinationIp(dstProto);
            arpInfo.setSourcePort(0);
            arpInfo.setDestinationPort(0);
            arpInfo.setProtocol("ARP");
            arpInfo.setTimestamp(LocalDateTime.now());
            arpInfo.setPacketLength(packet.length());
            arpInfo.setPayloadInfo("ARP Operation: " + arpPacket.getHeader().getOperation().value());
            // Default fields
            arpInfo.setFlags("-");
            arpInfo.setSequenceNumber(0);
            arpInfo.setAcknowledgmentNumber(0);
            arpInfo.setWindowSize(0);
            arpInfo.setPacketType("ARP");
            arpInfo.setPacketSummary(String.format("ARP %s -> %s Operation=%d", srcProto, dstProto, arpPacket.getHeader().getOperation().value()));
            arpInfo.setSourceLevel("ARPLive");
            arpInfo.setDestinationLevel("ARPLive");
            arpInfo.setCommunicationType("ARP Capture");
            arpInfo.setSourceManufacturer("ARP");
            arpInfo.setDestinationManufacturer("ARP");
            arpInfo.setSourceModel("ARP");
            arpInfo.setDestinationModel("ARP");
            return arpInfo;
        }

        IpPacket ipPacket = packet.get(IpPacket.class);
        if (ipPacket == null) return null; // Not an IP packet

        String srcIp = ipPacket.getHeader().getSrcAddr().getHostAddress();
        String dstIp = ipPacket.getHeader().getDstAddr().getHostAddress();
        String protocol = ipPacket.getHeader().getProtocol().name();
        int packetLength = packet.length(); // Full packet length
        LocalDateTime timestamp = (pcapTimestamp != null) 
                                ? pcapTimestamp.toLocalDateTime() 
                                : LocalDateTime.now(); // Use current time if pcap timestamp is null

        int srcPort = 0;
        int dstPort = 0;
        // This default is a last-resort label that should be overwritten by the
        // protocol-specific branches below. If the UI shows this, it means the
        // packet had no TCP/UDP/ICMP layer we could recognise (rare).
        String payloadInfo = "No recognisable payload";
        String flags = "-"; // Default flags
        int sequenceNumber = 0;
        int acknowledgmentNumber = 0;
        int windowSize = 0;

        // TCP Packet Details
        TcpPacket tcpPacket = ipPacket.get(TcpPacket.class);
        if (tcpPacket != null) {
            srcPort = tcpPacket.getHeader().getSrcPort().valueAsInt();
            dstPort = tcpPacket.getHeader().getDstPort().valueAsInt();
            sequenceNumber = tcpPacket.getHeader().getSequenceNumber();
            acknowledgmentNumber = tcpPacket.getHeader().getAcknowledgmentNumber();
            windowSize = tcpPacket.getHeader().getWindowAsInt();
            // Build flags string
            StringBuilder flagBuilder = new StringBuilder();
            if (tcpPacket.getHeader().getSyn()) flagBuilder.append("SYN ");
            if (tcpPacket.getHeader().getAck()) flagBuilder.append("ACK ");
            if (tcpPacket.getHeader().getFin()) flagBuilder.append("FIN ");
            if (tcpPacket.getHeader().getRst()) flagBuilder.append("RST ");
            if (tcpPacket.getHeader().getPsh()) flagBuilder.append("PSH ");
            if (tcpPacket.getHeader().getUrg()) flagBuilder.append("URG ");
            flags = flagBuilder.length() > 0 ? flagBuilder.toString().trim() : "-";
            // Detect IEC 60870-5-104 on TCP port 2404
            if ((srcPort == 2404 || dstPort == 2404) && tcpPacket.getPayload() != null) {
                protocol = "IEC104";
                byte[] raw = tcpPacket.getPayload().getRawData();
                if (raw != null && raw.length >= 6) { // Minimum IEC104 APDU length
                    ByteBuffer bb = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
                    int apciLength = bb.get() & 0xFF;
                    int typeId = bb.get() & 0xFF;
                    int numIx = bb.get() & 0xFF;
                    int cause = bb.get() & 0xFF;
                    int commonAddr = bb.get() & 0xFF;
                    
                    StringBuilder apduInfo = new StringBuilder();
                    apduInfo.append("IEC104 APDU: ");
                    
                    // APCI Type
                    String apciType = "";
                    if (apciLength == 4) apciType = "STARTDT";
                    else if (apciLength == 8) apciType = "STOPDT";
                    else if (apciLength == 12) apciType = "TEST";
                    else apciType = "I-Frame";
                    
                    apduInfo.append(apciType).append(" ");
                    
                    // Information Object Type
                    String infoType = "";
                    switch (typeId) {
                        case 1: infoType = "M_SP_NA_1 (Single Point)"; break;
                        case 3: infoType = "M_DP_NA_1 (Double Point)"; break;
                        case 9: infoType = "M_ME_NA_1 (Measured Value)"; break;
                        case 13: infoType = "M_ME_NC_1 (Float Value)"; break;
                        case 30: infoType = "M_SP_TB_1 (Single Point with Time)"; break;
                        case 45: infoType = "C_SC_NA_1 (Single Command)"; break;
                        case 58: infoType = "C_SE_NC_1 (Set Point Command)"; break;
                        case 100: infoType = "C_IC_NA_1 (Interrogation Command)"; break;
                        default: infoType = "Type " + typeId;
                    }
                    
                    apduInfo.append(infoType).append(" ");
                    
                    // Number of Information Objects
                    apduInfo.append("NumIX=").append(numIx).append(" ");
                    
                    // Cause of Transmission
                    String cot = "";
                    switch (cause) {
                        case 1: cot = "Periodic"; break;
                        case 2: cot = "Background"; break;
                        case 3: cot = "Spontaneous"; break;
                        case 4: cot = "Initialized"; break;
                        case 5: cot = "Request"; break;
                        case 6: cot = "Activation"; break;
                        case 7: cot = "Activation Confirmation"; break;
                        case 8: cot = "Deactivation"; break;
                        case 9: cot = "Deactivation Confirmation"; break;
                        case 10: cot = "Activation Termination"; break;
                        default: cot = "Cause " + cause;
                    }
                    
                    apduInfo.append("COT=").append(cot).append(" ");
                    
                    // Common Address
                    apduInfo.append("Addr=").append(commonAddr).append(" ");
                    
                    // Parse Information Objects if present
                    if (raw.length > 6) {
                        bb.position(6);
                        for (int i = 0; i < numIx && bb.remaining() >= 3; i++) {
                            int ioa = bb.get() & 0xFF;
                            ioa |= (bb.get() & 0xFF) << 8;
                            ioa |= (bb.get() & 0xFF) << 16;
                            
                            apduInfo.append("\nIOA=").append(ioa).append(" ");
                            
                            // Parse value based on type
                            switch (typeId) {
                                case 1: // M_SP_NA_1
                                    if (bb.remaining() >= 1) {
                                        int value = bb.get() & 0xFF;
                                        apduInfo.append("Value=").append((value & 0x01) == 1 ? "ON" : "OFF");
                                    }
                                    break;
                                case 3: // M_DP_NA_1
                                    if (bb.remaining() >= 1) {
                                        int value = bb.get() & 0xFF;
                                        String state = "";
                                        switch (value & 0x03) {
                                            case 0: state = "OFF"; break;
                                            case 1: state = "ON"; break;
                                            case 2: state = "INDETERMINATE"; break;
                                            case 3: state = "BAD"; break;
                                        }
                                        apduInfo.append("Value=").append(state);
                                    }
                                    break;
                                case 9: // M_ME_NA_1
                                    if (bb.remaining() >= 2) {
                                        int value = bb.getShort() & 0xFFFF;
                                        apduInfo.append("Value=").append(value);
                                    }
                                    break;
                                case 13: // M_ME_NC_1
                                    if (bb.remaining() >= 4) {
                                        float value = bb.getFloat();
                                        apduInfo.append("Value=").append(value);
                                    }
                                    break;
                            }
                        }
                    }
                    
                    payloadInfo = apduInfo.toString();
                } else {
                    payloadInfo = "IEC104 APDU Length: " + tcpPacket.getPayload().length();
                }
            } else if ((srcPort == 80 || dstPort == 80) && tcpPacket.getPayload() != null) {
                // Parse HTTP request/response first line
                byte[] raw = tcpPacket.getPayload().getRawData();
                if (raw != null) {
                    String text = new String(raw, StandardCharsets.UTF_8);
                    String[] lines = text.split("\r?\n");
                    
                    payloadInfo = lines.length > 0 ? "HTTP: " + lines[0] : "HTTP payload";
                } else {
                    payloadInfo = "HTTP (no payload)";
                }
            } else if (tcpPacket.getPayload() != null) {
                payloadInfo = "TCP Payload Length: " + tcpPacket.getPayload().length();
            } else {
                // No TCP payload - surface the control-segment role so the UI
                // stops showing "Payload not parsed" for handshake/keepalive.
                String fl = flags.trim();
                if (fl.equals("SYN"))            payloadInfo = "TCP handshake · SYN";
                else if (fl.contains("SYN") && fl.contains("ACK")) payloadInfo = "TCP handshake · SYN-ACK";
                else if (fl.contains("FIN") && fl.contains("ACK")) payloadInfo = "TCP close · FIN-ACK";
                else if (fl.contains("FIN"))     payloadInfo = "TCP close · FIN";
                else if (fl.contains("RST"))     payloadInfo = "TCP reset · RST";
                else if (fl.equals("ACK"))       payloadInfo = "TCP control · ACK (no data)";
                else if (fl.isEmpty() || fl.equals("-")) payloadInfo = "TCP control · no flags";
                else                              payloadInfo = "TCP control · [" + fl + "]";
            }
        } else {
            // UDP Packet Details
            UdpPacket udpPacket = ipPacket.get(UdpPacket.class);
            if (udpPacket != null) {
                srcPort = udpPacket.getHeader().getSrcPort().valueAsInt();
                dstPort = udpPacket.getHeader().getDstPort().valueAsInt();
                if (udpPacket.getPayload() != null) {
                    // Check for DNS packets
                    DnsPacket dns = packet.get(DnsPacket.class);
                    if (dns != null && dns.getHeader().getQuestions() != null && !dns.getHeader().getQuestions().isEmpty()) {
                        payloadInfo = "DNS Query: " + dns.getHeader().getQuestions().stream()
                            .map(q -> q.getQName().getName())
                            .collect(Collectors.joining(", "));
                    } else {
                        payloadInfo = "UDP Payload Length: " + udpPacket.getPayload().length();
                    }
                }
            } else {
                // ICMP Packet Details Check (now starts with 'if', not 'else if')
                if (ipPacket.getHeader().getProtocol() == IpNumber.ICMPV4 || ipPacket.getHeader().getProtocol() == IpNumber.ICMPV6) {
                    IcmpV4CommonPacket icmpV4 = packet.get(IcmpV4CommonPacket.class);
                    if (icmpV4 != null) {
                        // Construct a more informative summary for ICMP
                        payloadInfo = String.format("ICMPv4 Type=%s(%d), Code=%s(%d)",
                                icmpV4.getHeader().getType().name(),
                                icmpV4.getHeader().getType().value(),
                                icmpV4.getHeader().getCode().name(),
                                icmpV4.getHeader().getCode().value()
                        );
                    }
                    // TODO: Add specific ICMPv6 parsing if needed (IcmpV6CommonPacket)
                } else {
                    // Other IP protocols (payload not parsed in detail here)
                    payloadInfo = String.format("IP Protocol: %s (%d)",
                            ipPacket.getHeader().getProtocol().name(),
                            ipPacket.getHeader().getProtocol().value());
                }
            }
        }

        // Create PacketInfo using no-arg constructor and setters
        PacketInfo packetInfo = new PacketInfo();
        packetInfo.setSourceIp(srcIp);
        packetInfo.setDestinationIp(dstIp);
        packetInfo.setSourcePort(srcPort);
        packetInfo.setDestinationPort(dstPort);
        packetInfo.setProtocol(protocol);
        packetInfo.setTimestamp(timestamp); // Set LocalDateTime
        packetInfo.setPacketLength(packetLength);
        packetInfo.setPayloadInfo(payloadInfo); // Updated payloadInfo
        packetInfo.setFlags(flags);
        packetInfo.setSequenceNumber(sequenceNumber);
        packetInfo.setAcknowledgmentNumber(acknowledgmentNumber);
        packetInfo.setWindowSize(windowSize);
        packetInfo.setPacketType(ipPacket instanceof IpV4Packet ? "IPv4" : (ipPacket instanceof IpV6Packet ? "IPv6" : "IP"));
        packetInfo.setPacketSummary(String.format("%s %s%s -> %s%s Len=%d Flags=[%s] Seq=%d Ack=%d Win=%d",
                protocol,
                srcIp, srcPort != 0 ? ":" + srcPort : "",
                dstIp, dstPort != 0 ? ":" + dstPort : "",
                packetLength,
                flags,
                sequenceNumber,
                acknowledgmentNumber,
                windowSize
        )); // More detailed summary
        
        // Set placeholders or implement logic for Purdue levels/Comm Type/Manufacturer/Model
        packetInfo.setSourceLevel("Live"); // Placeholder
        packetInfo.setDestinationLevel("Live"); // Placeholder
        packetInfo.setCommunicationType("Live Capture"); // Placeholder
        
        // Determine manufacturer and model information
        EthernetPacket eth = packet.get(EthernetPacket.class);
        if (eth != null) {
            String srcMac = eth.getHeader().getSrcAddr().toString().toUpperCase();
            String dstMac = eth.getHeader().getDstAddr().toString().toUpperCase();
            String srcOUI = srcMac.length() >= 8 ? srcMac.substring(0, 8) : srcMac;
            String dstOUI = dstMac.length() >= 8 ? dstMac.substring(0, 8) : dstMac;
            
            // Set manufacturers from OUI lookup
            packetInfo.setSourceManufacturer(ouiMap.getOrDefault(srcOUI, "Unknown"));
            packetInfo.setDestinationManufacturer(ouiMap.getOrDefault(dstOUI, "Unknown"));
            
            // Check for CDP/LLDP model info first
            String srcModel = cdpModelMap.getOrDefault(srcMac, lldpModelMap.getOrDefault(srcMac, "Unknown"));
            String dstModel = cdpModelMap.getOrDefault(dstMac, lldpModelMap.getOrDefault(dstMac, "Unknown"));
            
            // If no CDP/LLDP info, try protocol-based mapping
            if ("Unknown".equals(srcModel)) {
                srcModel = PROTOCOL_MODEL_MAP.getOrDefault(protocol, "Generic Device");
            }
            if ("Unknown".equals(dstModel)) {
                dstModel = PROTOCOL_MODEL_MAP.getOrDefault(protocol, "Generic Device");
            }
            
            // For specific protocols, try to extract more detailed model info
            if (tcpPacket != null) {
                // HTTP User-Agent analysis for device identification
                if ((srcPort == 80 || dstPort == 80) && tcpPacket.getPayload() != null) {
                    byte[] raw = tcpPacket.getPayload().getRawData();
                    if (raw != null) {
                        String text = new String(raw, StandardCharsets.UTF_8);
                        String[] lines = text.split("\r?\n");
                        
                        // Extract User-Agent for device identification
                        String userAgent = null;
                        for (String line : lines) {
                            if (line.toLowerCase().startsWith("user-agent:")) {
                                userAgent = line.substring(12).trim();
                                break;
                            }
                        }
                        
                        if (userAgent != null) {
                            String deviceModel = parseUserAgentForModel(userAgent);
                            if (deviceModel != null) {
                                if (srcPort == 80) {
                                    srcModel = deviceModel;
                                } else {
                                    dstModel = deviceModel;
                                }
                            }
                        }
                    }
                }
                
                // EtherNet/IP (CIP) on port 44818
                if ((srcPort == 44818 || dstPort == 44818) && tcpPacket.getPayload() != null) {
                    byte[] raw = tcpPacket.getPayload().getRawData();
                    if (raw != null) {
                        CipIdentity id = parseCipIdentity(raw);
                        if (id != null) {
                            if (srcPort == 44818) {
                                srcModel = id.getModelString();
                            }
                            if (dstPort == 44818) {
                                dstModel = id.getModelString();
                            }
                        }
                    }
                }
                // Modbus TCP on port 502 - full DPI dissection (function code,
                // register address, value, exception code, etc.)
                else if ((srcPort == 502 || dstPort == 502) && tcpPacket.getPayload() != null) {
                    byte[] raw = tcpPacket.getPayload().getRawData();
                    String summary = ModbusDissector.dissect(raw, srcPort, dstPort, packetInfo);
                    if (summary != null) {
                        // Promote protocol label + rewrite payloadInfo with the
                        // rich summary produced by the dissector.
                        packetInfo.setProtocol("MODBUS");
                        packetInfo.setPayloadInfo(summary);
                        String unitId = packetInfo.getDpiFields().get("unit_id");
                        String modbusModel = unitId != null ? "Modbus Unit " + unitId : "Modbus Device";
                        if (srcPort == 502) srcModel = modbusModel;
                        if (dstPort == 502) dstModel = modbusModel;
                    } else if (raw != null && raw.length >= 7) {
                        // Fallback: keep legacy Unit-ID-only behaviour so we
                        // never regress display when MBAP header is malformed.
                        int unitId = raw[6] & 0xFF;
                        String modbusModel = String.format("Modbus Unit %d", unitId);
                        if (srcPort == 502) srcModel = modbusModel;
                        if (dstPort == 502) dstModel = modbusModel;
                    }
                }
                // Siemens S7Comm on port 102 (ISO-on-TCP) - full DPI dissection
                // (ROSCTR, function code, area/DB/address, PLC control)
                else if ((srcPort == 102 || dstPort == 102) && tcpPacket.getPayload() != null) {
                    byte[] raw = tcpPacket.getPayload().getRawData();
                    String summary = S7CommDissector.dissect(raw, srcPort, dstPort, packetInfo);
                    if (summary != null) {
                        packetInfo.setProtocol("S7COMM");
                        packetInfo.setPayloadInfo(summary);
                        String s7Model = "Siemens S7 PLC";
                        if (srcPort == 102) srcModel = s7Model;
                        if (dstPort == 102) dstModel = s7Model;
                    }
                }
                // IEC 60870-5-104 on port 2404
                else if ((srcPort == 2404 || dstPort == 2404) && tcpPacket.getPayload() != null) {
                    String iecModel = "IEC 60870-5-104 Device";
                    if (srcPort == 2404) {
                        srcModel = iecModel;
                    }
                    if (dstPort == 2404) {
                        dstModel = iecModel;
                    }
                }
                // SNMP on port 161/162
                else if ((srcPort == 161 || dstPort == 161 || srcPort == 162 || dstPort == 162) && tcpPacket.getPayload() != null) {
                    String snmpModel = "SNMP Device";
                    if (srcPort == 161 || srcPort == 162) {
                        srcModel = snmpModel;
                    }
                    if (dstPort == 161 || dstPort == 162) {
                        dstModel = snmpModel;
                    }
                }
                // Port-agnostic Modbus heuristic - last resort for Modbus
                // traffic on non-standard ports (Conpot defaults to 5020,
                // some OT dev setups use 1502). Only triggers when no other
                // protocol-specific branch above matched AND the MBAP header
                // looks legitimate (proto_id=0, length field sane).
                else if (!"MODBUS".equals(packetInfo.getProtocol())
                         && !"S7COMM".equals(packetInfo.getProtocol())
                         && tcpPacket.getPayload() != null) {
                    byte[] raw = tcpPacket.getPayload().getRawData();
                    if (raw != null && raw.length >= 8) {
                        int protoId = ((raw[2] & 0xFF) << 8) | (raw[3] & 0xFF);
                        int lenField = ((raw[4] & 0xFF) << 8) | (raw[5] & 0xFF);
                        if (protoId == 0 && lenField >= 2 && lenField <= raw.length - 6 + 1) {
                            String summary = ModbusDissector.dissect(raw, srcPort, dstPort, packetInfo);
                            if (summary != null) {
                                packetInfo.setProtocol("MODBUS");
                                packetInfo.setPayloadInfo(summary);
                                String unitId = packetInfo.getDpiFields().get("unit_id");
                                String modbusModel = unitId != null ? "Modbus Unit " + unitId : "Modbus Device";
                                srcModel = modbusModel;
                                dstModel = modbusModel;
                            }
                        }
                    }
                }
            }

            packetInfo.setSourceModel(srcModel);
            packetInfo.setDestinationModel(dstModel);
        } else {
            packetInfo.setSourceManufacturer("Unknown");
            packetInfo.setDestinationManufacturer("Unknown");
            packetInfo.setSourceModel("Unknown");
            packetInfo.setDestinationModel("Unknown");
        }
        
        // LLDP parsing: capture System Description TLV from LLDP frames (EtherType 0x88CC)
        EthernetPacket lldpEth = packet.get(EthernetPacket.class);
        if (lldpEth != null && lldpEth.getPayload() != null && lldpEth.getHeader().getType().value() == 0x88CC) {
            byte[] raw = lldpEth.getPayload().getRawData();
            ByteBuffer bb = ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);
            
            while (bb.remaining() >= 2) {
                int tlvType = bb.get() & 0xFF;
                int tlvLen = bb.get() & 0xFF;
                if (tlvLen > bb.remaining()) break;
                
                byte[] val = new byte[tlvLen];
                bb.get(val);
                
                // System Description TLV (Type 6)
                if (tlvType == 6) {
                    String systemDesc = new String(val, StandardCharsets.UTF_8).trim();
                    if (!systemDesc.isEmpty()) {
                        lldpModelMap.put(lldpEth.getHeader().getSrcAddr().toString(), systemDesc);
                    }
                }
                // System Name TLV (Type 5) - alternative model info
                else if (tlvType == 5) {
                    String systemName = new String(val, StandardCharsets.UTF_8).trim();
                    if (!systemName.isEmpty()) {
                        lldpModelMap.put(lldpEth.getHeader().getSrcAddr().toString(), systemName);
                    }
                }
            }
            return null; // skip IP parsing for pure LLDP frames
        }
        
        return packetInfo;
    }

    /**
     * Parses User-Agent string to extract device model information
     */
    private String parseUserAgentForModel(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return null;
        }
        
        String ua = userAgent.toLowerCase();
        
        // Siemens devices
        if (ua.contains("simatic") || ua.contains("siemens")) {
            if (ua.contains("s7-1200")) return "SIMATIC S7-1200";
            if (ua.contains("s7-1500")) return "SIMATIC S7-1500";
            if (ua.contains("s7-300")) return "SIMATIC S7-300";
            if (ua.contains("s7-400")) return "SIMATIC S7-400";
            return "Siemens Device";
        }
        
        // Rockwell/Allen-Bradley devices
        if (ua.contains("allen-bradley") || ua.contains("rockwell")) {
            if (ua.contains("controllogix")) return "ControlLogix";
            if (ua.contains("compactlogix")) return "CompactLogix";
            if (ua.contains("micrologix")) return "MicroLogix";
            return "Allen-Bradley Device";
        }
        
        // Schneider Electric devices
        if (ua.contains("schneider") || ua.contains("modicon")) {
            if (ua.contains("m340")) return "Modicon M340";
            if (ua.contains("m580")) return "Modicon M580";
            if (ua.contains("premium")) return "Modicon Premium";
            return "Schneider Device";
        }
        
        // Generic industrial web servers
        if (ua.contains("embedded") || ua.contains("industrial")) {
            return "Industrial Web Server";
        }
        
        return null;
    }

    /**
     * Parses CIP Identity (ListIdentity) response from EtherNet/IP payload.
     */
    private CipIdentity parseCipIdentity(byte[] data) {
        ByteBuffer bb = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN);
        final int ENIP_HEADER_LEN = 24;
        if (data.length < ENIP_HEADER_LEN + 8) return null;
        bb.position(ENIP_HEADER_LEN);
        int vendorId = bb.getShort() & 0xFFFF;
        int deviceType = bb.getShort() & 0xFFFF;
        int productCode = bb.getShort() & 0xFFFF;
        int majorRev = bb.get() & 0xFF;
        int minorRev = bb.get() & 0xFF;
        String vendor = CIP_VENDOR_MAP.getOrDefault(vendorId, "VendorID:" + vendorId);
        return new CipIdentity(vendor, deviceType, productCode, majorRev, minorRev);
    }

    private static class CipIdentity {
        private final String vendor;
        private final int deviceType, productCode, majorRev, minorRev;
        public CipIdentity(String vendor, int deviceType, int productCode, int majorRev, int minorRev) {
            this.vendor = vendor;
            this.deviceType = deviceType;
            this.productCode = productCode;
            this.majorRev = majorRev;
            this.minorRev = minorRev;
        }
        public String getModelString() {
            return String.format("%s D:%d P:%d v%d.%d", vendor, deviceType, productCode, majorRev, minorRev);
        }
    }

    @PreDestroy
    public void onDestroy() {
        logger.info("PcapAnalysisService shutting down, stopping capture...");
        stopLiveCapture();
        
        // Cleanup WebSocket handler if available
        if (packetHandler != null) {
            try {
                packetHandler.cleanup();
            } catch (Exception e) {
                logger.warn("Error cleaning up WebSocket handler: {}", e.getMessage());
            }
        }
    }

    /**
     * Detect and save new assets from packet analysis
     */
    public void detectAndSaveAssets(List<PacketInfo> packets) {
        logger.info("Starting asset detection from {} packets", packets.size());
        
        List<AssetDTO> newAssets = new ArrayList<>();
        
        for (PacketInfo packet : packets) {
            // Detect source asset
            detectAssetFromPacket(packet, packet.getSourceIp(), packet.getSourceManufacturer(), 
                                packet.getSourceModel(), packet.getSourceLevel(), newAssets);
            
            // Detect destination asset
            detectAssetFromPacket(packet, packet.getDestinationIp(), packet.getDestinationManufacturer(), 
                                packet.getDestinationModel(), packet.getDestinationLevel(), newAssets);
        }
        
        // Save new assets to database
        if (!newAssets.isEmpty()) {
            saveNewAssets(newAssets);
        }
        
        logger.info("Asset detection completed. Found {} new assets", newAssets.size());
    }

    /**
     * Detect asset from packet information
     */
    private void detectAssetFromPacket(PacketInfo packet, String ipAddress, String manufacturer, 
                                     String model, String level, List<AssetDTO> newAssets) {
        
        // Skip if IP is null, empty, or already detected
        if (ipAddress == null || ipAddress.isEmpty() || detectedIpAddresses.contains(ipAddress)) {
            return;
        }
        
        // Skip private IPs for external assets (but allow internal asset detection)
        if (isPrivateIp(ipAddress) && !isValidInternalAsset(ipAddress, manufacturer, model)) {
            return;
        }
        
        // Check if asset already exists in database
        if (assetService.assetExistsByIpAddress(ipAddress)) {
            // Even though the asset is already known, an earlier ingest may
            // have stamped it with the placeholder Purdue level (everything
            // bucketed to LEVEL_3 because the dissector emitted "Live"
            // before inferPurdueLevel landed). Rules like
            // dpi.unauthorized_write are silent for those legacy rows.
            // Upgrade them in-place when the IP subnet maps to a *different*
            // (and more accurate) level than what's currently stored.
            upgradePurdueLevelIfMisaligned(ipAddress);
            detectedIpAddresses.add(ipAddress);
            return;
        }
        
        // Create new asset
        AssetDTO asset = createAssetFromPacketInfo(ipAddress, manufacturer, model, level, packet);
        
        if (asset != null) {
            newAssets.add(asset);
            detectedIpAddresses.add(ipAddress);
            logger.debug("Detected new asset: {} ({})", ipAddress, asset.getName());
        }
    }

    /**
     * Create AssetDTO from packet information
     */
    private AssetDTO createAssetFromPacketInfo(String ipAddress, String manufacturer, String model, 
                                             String level, PacketInfo packet) {
        
        AssetDTO asset = new AssetDTO();
        
        // Basic information
        asset.setIpAddress(ipAddress);
        asset.setName(generateAssetName(ipAddress, manufacturer, model));
        asset.setDescription(generateAssetDescription(ipAddress, manufacturer, model, level));
        
        // Asset type and category based on manufacturer and model
        Asset.AssetType assetType = determineAssetType(manufacturer, model, packet.getProtocol());
        Asset.AssetCategory assetCategory = determineAssetCategory(assetType, level);
        // Purdue level: prefer an explicit LEVEL_X string from the dissector;
        // otherwise infer from the IP subnet so the OTShield demo lab
        // (10.10.0.x=L0, 10.10.1.x=L2 HMI, 10.10.2.x=L1 PLC, 10.20.0.x=L3)
        // classifies newly-discovered hosts correctly. Without this, rules
        // like dpi.unauthorized_write that depend on Purdue levels stay silent
        // because every auto-detected asset defaults to LEVEL_3.
        Asset.PurdueLevel purdueLevel = inferPurdueLevel(level, ipAddress);
        
        asset.setAssetType(assetType);
        asset.setAssetCategory(assetCategory);
        asset.setPurdueLevel(purdueLevel);
        
        // Manufacturer and model information
        asset.setManufacturer(manufacturer != null ? manufacturer : "Unknown");
        asset.setModel(model != null ? model : "Unknown");
        
        // Criticality based on Purdue level and asset type
        Asset.CriticalityLevel criticalityLevel = determineCriticalityLevel(purdueLevel, assetType);
        asset.setCriticalityLevel(criticalityLevel);
        
        // Risk score based on criticality and vulnerabilities
        int riskScore = calculateRiskScore(criticalityLevel, assetType, purdueLevel);
        asset.setRiskScore(riskScore);
        
        // Default values
        asset.setIsActive(true);
        asset.setIsOnline(true);
        asset.setMonitoringStatus(Asset.MonitoringStatus.NOT_MONITORED);
        asset.setBackupStatus(Asset.BackupStatus.NOT_CONFIGURED);
        asset.setVulnerabilityCount(0);
        
        // Tags
        List<String> tags = new ArrayList<>();
        if (manufacturer != null && !manufacturer.equals("Unknown")) {
            tags.add(manufacturer.toLowerCase().replace(" ", "-"));
        }
        if (model != null && !model.equals("Unknown")) {
            tags.add(model.toLowerCase().replace(" ", "-"));
        }
        tags.add(assetType.name().toLowerCase());
        tags.add(purdueLevel.name().toLowerCase());
        tags.add("auto-detected");
        asset.setTags(tags);
        
        return asset;
    }

    /**
     * Save new assets to database
     */
    private void saveNewAssets(List<AssetDTO> newAssets) {
        logger.info("Saving {} new assets to database", newAssets.size());
        
        for (AssetDTO asset : newAssets) {
            try {
                AssetDTO savedAsset = assetService.createAsset(asset);
                logger.info("Saved new asset: {} ({})", savedAsset.getName(), savedAsset.getIpAddress());
            } catch (Exception e) {
                logger.error("Error saving asset {}: {}", asset.getIpAddress(), e.getMessage());
            }
        }
    }

    /**
     * Generate asset name from IP and manufacturer/model
     */
    private String generateAssetName(String ipAddress, String manufacturer, String model) {
        if (manufacturer != null && !manufacturer.equals("Unknown")) {
            if (model != null && !model.equals("Unknown")) {
                return String.format("%s-%s-%s", manufacturer, model, ipAddress.replace(".", "-"));
            } else {
                return String.format("%s-Device-%s", manufacturer, ipAddress.replace(".", "-"));
            }
        } else {
            return String.format("Unknown-Device-%s", ipAddress.replace(".", "-"));
        }
    }

    /**
     * Generate asset description
     */
    private String generateAssetDescription(String ipAddress, String manufacturer, String model, String level) {
        StringBuilder description = new StringBuilder();
        
        if (manufacturer != null && !manufacturer.equals("Unknown")) {
            description.append(manufacturer);
            if (model != null && !model.equals("Unknown")) {
                description.append(" ").append(model);
            }
        } else {
            description.append("Unknown device");
        }
        
        description.append(" at IP ").append(ipAddress);
        
        if (level != null && !level.isEmpty()) {
            description.append(" in ").append(level);
        }
        
        description.append(" (Auto-detected from network traffic)");
        
        return description.toString();
    }

    /**
     * Determine asset type based on manufacturer, model, and protocol
     */
    private Asset.AssetType determineAssetType(String manufacturer, String model, String protocol) {
        if (manufacturer != null) {
            String manufLower = manufacturer.toLowerCase();
            String modelLower = model != null ? model.toLowerCase() : "";
            
            // PLC detection
            if (manufLower.contains("siemens") && modelLower.contains("simatic")) {
                return Asset.AssetType.PLC;
            }
            if (manufLower.contains("rockwell") || manufLower.contains("allen-bradley")) {
                if (modelLower.contains("logix") || modelLower.contains("micrologix")) {
                    return Asset.AssetType.PLC;
                }
            }
            if (manufLower.contains("schneider") && modelLower.contains("modicon")) {
                return Asset.AssetType.PLC;
            }
            
            // HMI detection
            if (modelLower.contains("panelview") || modelLower.contains("hmi")) {
                return Asset.AssetType.HMI;
            }
            
            // SCADA detection
            if (modelLower.contains("wincc") || modelLower.contains("scada")) {
                return Asset.AssetType.SCADA;
            }
            
            // Network device detection
            if (manufLower.contains("cisco")) {
                if (modelLower.contains("router") || modelLower.contains("isr")) {
                    return Asset.AssetType.ROUTER;
                }
                if (modelLower.contains("switch") || modelLower.contains("catalyst")) {
                    return Asset.AssetType.SWITCH;
                }
                if (modelLower.contains("firewall") || modelLower.contains("asa")) {
                    return Asset.AssetType.FIREWALL;
                }
            }
            
            // Server detection
            if (modelLower.contains("server") || modelLower.contains("proliant")) {
                return Asset.AssetType.SERVER;
            }
        }
        
        // Protocol-based detection
        if (protocol != null) {
            switch (protocol.toUpperCase()) {
                case "MODBUS":
                case "DNP3":
                case "IEC104":
                    return Asset.AssetType.PLC;
                case "HTTP":
                case "HTTPS":
                    return Asset.AssetType.APPLICATION;
                case "SNMP":
                    return Asset.AssetType.IDS_IPS;
                default:
                    break;
            }
        }
        
        return Asset.AssetType.OTHER;
    }

    /**
     * Determine asset category based on asset type and level
     */
    private Asset.AssetCategory determineAssetCategory(Asset.AssetType assetType, String level) {
        switch (assetType) {
            case PLC:
            case HMI:
            case SCADA:
            case RTU:
            case DCS:
                return Asset.AssetCategory.CONTROL_SYSTEM;
            case ROUTER:
            case SWITCH:
                return Asset.AssetCategory.NETWORK_INFRASTRUCTURE;
            case FIREWALL:
            case IDS_IPS:
                return Asset.AssetCategory.SECURITY_DEVICE;
            case SERVER:
            case DATABASE:
            case HISTORIAN:
                return Asset.AssetCategory.DATA_STORAGE;
            case WORKSTATION:
                return Asset.AssetCategory.ENDPOINT;
            case SENSOR:
            case ACTUATOR:
                return Asset.AssetCategory.FIELD_DEVICE;
            default:
                return Asset.AssetCategory.OTHER;
        }
    }

    /**
     * Backfill / repair the Purdue level on a pre-existing asset when the
     * stored level doesn't match what the IP subnet says it should be.
     *
     * <p>This exists because earlier ingest runs (before
     * {@link #inferPurdueLevel(String, String)} landed) wrote {@code LEVEL_3}
     * for every auto-detected host - the dissector hands us {@code "Live"}
     * as the level string, and {@link #mapToPurdueLevel(String)}'s null/unknown
     * branch defaults to LEVEL_3. As a result, hosts on the
     * {@code 10.10.1.0/24} HMI subnet got persisted as LEVEL_3 instead of
     * LEVEL_2, the {@code dpi.unauthorized_write} rule sees no zone delta,
     * and demo scenarios stay silent.
     *
     * <p>Rather than force the user to delete the row from the UI (the
     * Asset list has no delete button on every screen), we opportunistically
     * upgrade it on the next pcap upload. Only a level mismatch against the
     * IP-subnet heuristic triggers an update - dissector-supplied real
     * levels are still respected.
     */
    private void upgradePurdueLevelIfMisaligned(String ipAddress) {
        Asset.PurdueLevel target = levelFromIpSubnet(ipAddress);
        if (target == null) return; // unknown subnet - leave it alone

        try {
            assetService.getAssetByIpAddress(ipAddress).ifPresent(dto -> {
                Asset.PurdueLevel current = dto.getPurdueLevel();
                if (current == target) return; // already correct
                logger.info("Upgrading Purdue level for asset {} ({}): {} -> {}",
                        dto.getId(), ipAddress, current, target);
                dto.setPurdueLevel(target);
                // Keep tags consistent so downstream consumers (filters,
                // reports) don't see a stale `level_3` tag on an L2 asset.
                if (dto.getTags() != null) {
                    List<String> tags = new ArrayList<>(dto.getTags());
                    if (current != null) {
                        tags.removeIf(t -> t != null && t.equalsIgnoreCase(current.name()));
                    }
                    String newTag = target.name().toLowerCase();
                    if (tags.stream().noneMatch(t -> t != null && t.equalsIgnoreCase(newTag))) {
                        tags.add(newTag);
                    }
                    dto.setTags(tags);
                }
                assetService.updateAsset(dto.getId(), dto);
            });
        } catch (Exception e) {
            logger.warn("Failed to upgrade Purdue level for {}: {}", ipAddress, e.getMessage());
        }
    }

    /**
     * Infer Purdue level for an auto-detected asset. Uses the dissector's
     * level string when it is explicit (e.g. "LEVEL_1"), and falls back to
     * an IP-subnet heuristic that matches the OTShield demo lab layout.
     *
     * <p>The fallback is critical: the live-capture and most pcap code paths
     * currently stamp a placeholder like "Live" on every packet, which means
     * {@link #mapToPurdueLevel(String)} would bucket every host into LEVEL_3,
     * silencing any rule that depends on Purdue deltas (notably
     * {@code dpi.unauthorized_write}).
     *
     * <p>Subnet map (align with demo docs and seed data):
     * <ul>
     *   <li>{@code 10.10.0.0/24} - field devices (L0)</li>
     *   <li>{@code 10.10.1.0/24} - HMIs / area SCADA (L2)</li>
     *   <li>{@code 10.10.2.0/24} - PLCs / controllers (L1)</li>
     *   <li>{@code 10.20.0.0/24} - engineering workstations (L3)</li>
     *   <li>{@code 10.30.0.0/24} - DMZ / jump hosts (L4)</li>
     *   <li>{@code 10.40.0.0/24} - enterprise IT (L5)</li>
     * </ul>
     */
    private Asset.PurdueLevel inferPurdueLevel(String level, String ipAddress) {
        // Trust an explicit level string from the dissector if it actually
        // parses to a real enum value (i.e. it wasn't the "Live" placeholder).
        if (level != null) {
            String norm = level.trim().toUpperCase();
            if (norm.startsWith("LEVEL") || norm.equals("DMZ") || norm.equals("ENTERPRISE")) {
                return mapToPurdueLevel(level);
            }
        }
        // Fall back to the lab's IP-subnet heuristic.
        Asset.PurdueLevel fromIp = levelFromIpSubnet(ipAddress);
        if (fromIp != null) return fromIp;
        // Final fallback: existing behaviour (LEVEL_3).
        return mapToPurdueLevel(level);
    }

    /**
     * Map an IPv4 address to a Purdue level using the lab subnet convention.
     * Returns null if the address does not match any known range - callers
     * should fall back to a sensible default in that case.
     */
    private Asset.PurdueLevel levelFromIpSubnet(String ipAddress) {
        if (ipAddress == null) return null;
        // Quick octet parse; avoid regex overhead for the common case.
        String[] parts = ipAddress.split("\\.");
        if (parts.length != 4) return null;
        int a, b, c;
        try {
            a = Integer.parseInt(parts[0]);
            b = Integer.parseInt(parts[1]);
            c = Integer.parseInt(parts[2]);
        } catch (NumberFormatException e) {
            return null;
        }
        if (a == 10 && b == 10) {
            switch (c) {
                case 0: return Asset.PurdueLevel.LEVEL_0;  // field devices
                case 1: return Asset.PurdueLevel.LEVEL_2;  // HMI / area SCADA
                case 2: return Asset.PurdueLevel.LEVEL_1;  // PLCs
                default: return Asset.PurdueLevel.LEVEL_1; // other OT hosts → controller default
            }
        }
        if (a == 10 && b == 20) return Asset.PurdueLevel.LEVEL_3; // engineering workstations
        if (a == 10 && b == 30) return Asset.PurdueLevel.LEVEL_4; // DMZ
        if (a == 10 && b == 40) return Asset.PurdueLevel.LEVEL_5; // enterprise
        return null;
    }

    /**
     * Map level string to Purdue level enum
     */
    private Asset.PurdueLevel mapToPurdueLevel(String level) {
        if (level == null) {
            return Asset.PurdueLevel.LEVEL_3; // Default to Level 3
        }
        
        switch (level.toUpperCase()) {
            case "LEVEL 0":
            case "LEVEL_0":
                return Asset.PurdueLevel.LEVEL_0;
            case "LEVEL 1":
            case "LEVEL_1":
                return Asset.PurdueLevel.LEVEL_1;
            case "LEVEL 2":
            case "LEVEL_2":
                return Asset.PurdueLevel.LEVEL_2;
            case "LEVEL 3":
            case "LEVEL_3":
                return Asset.PurdueLevel.LEVEL_3;
            case "LEVEL 4":
            case "LEVEL_4":
            case "DMZ":
                return Asset.PurdueLevel.LEVEL_4;
            case "LEVEL 5":
            case "LEVEL_5":
            case "ENTERPRISE":
                return Asset.PurdueLevel.LEVEL_5;
            default:
                return Asset.PurdueLevel.LEVEL_3;
        }
    }

    /**
     * Determine criticality level based on Purdue level and asset type
     */
    private Asset.CriticalityLevel determineCriticalityLevel(Asset.PurdueLevel purdueLevel, Asset.AssetType assetType) {
        // Critical assets: Level 0-1 control systems
        if (purdueLevel == Asset.PurdueLevel.LEVEL_0 || purdueLevel == Asset.PurdueLevel.LEVEL_1) {
            if (assetType == Asset.AssetType.PLC || assetType == Asset.AssetType.HMI || 
                assetType == Asset.AssetType.SCADA || assetType == Asset.AssetType.RTU) {
                return Asset.CriticalityLevel.CRITICAL;
            }
        }
        
        // High criticality: Level 2 supervisory systems, security devices
        if (purdueLevel == Asset.PurdueLevel.LEVEL_2 || 
            assetType == Asset.AssetType.FIREWALL || assetType == Asset.AssetType.IDS_IPS) {
            return Asset.CriticalityLevel.HIGH;
        }
        
        // Medium criticality: Level 3 business systems, servers
        if (purdueLevel == Asset.PurdueLevel.LEVEL_3 || assetType == Asset.AssetType.SERVER) {
            return Asset.CriticalityLevel.MEDIUM;
        }
        
        // Low criticality: Level 4-5, workstations
        if (purdueLevel == Asset.PurdueLevel.LEVEL_4 || purdueLevel == Asset.PurdueLevel.LEVEL_5 ||
            assetType == Asset.AssetType.WORKSTATION) {
            return Asset.CriticalityLevel.LOW;
        }
        
        return Asset.CriticalityLevel.MEDIUM;
    }

    /**
     * Calculate risk score based on criticality and other factors
     */
    private int calculateRiskScore(Asset.CriticalityLevel criticalityLevel, Asset.AssetType assetType, Asset.PurdueLevel purdueLevel) {
        int baseScore = 0;
        
        // Base score from criticality
        switch (criticalityLevel) {
            case CRITICAL:
                baseScore = 90;
                break;
            case HIGH:
                baseScore = 70;
                break;
            case MEDIUM:
                baseScore = 50;
                break;
            case LOW:
                baseScore = 30;
                break;
            case MINIMAL:
                baseScore = 10;
                break;
        }
        
        // Adjustments based on asset type
        if (assetType == Asset.AssetType.FIREWALL || assetType == Asset.AssetType.IDS_IPS) {
            baseScore += 10; // Security devices get higher risk
        }
        
        if (assetType == Asset.AssetType.WORKSTATION) {
            baseScore -= 10; // Workstations get lower risk
        }
        
        // Adjustments based on Purdue level
        if (purdueLevel == Asset.PurdueLevel.LEVEL_0) {
            baseScore += 15; // Process level gets highest risk
        }
        
        return Math.min(100, Math.max(0, baseScore));
    }

    /**
     * Check if IP address is private
     */
    private boolean isPrivateIp(String ipAddress) {
        if (ipAddress == null) return false;
        
        String[] parts = ipAddress.split("\\.");
        if (parts.length != 4) return false;
        
        try {
            int first = Integer.parseInt(parts[0]);
            int second = Integer.parseInt(parts[1]);
            
            // Private IP ranges
            return (first == 10) || 
                   (first == 172 && second >= 16 && second <= 31) || 
                   (first == 192 && second == 168);
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * Check if this is a valid internal asset worth tracking
     */
    private boolean isValidInternalAsset(String ipAddress, String manufacturer, String model) {
        // Always track assets with known manufacturers
        if (manufacturer != null && !manufacturer.equals("Unknown")) {
            return true;
        }
        
        // Always track assets with known models
        if (model != null && !model.equals("Unknown")) {
            return true;
        }
        
        // Track assets in common industrial IP ranges
        String[] parts = ipAddress.split("\\.");
        if (parts.length == 4) {
            try {
                int first = Integer.parseInt(parts[0]);
                int second = Integer.parseInt(parts[1]);
                
                // Common industrial network ranges
                return (first == 192 && second == 168) || // Common industrial networks
                       (first == 10 && second >= 0 && second <= 255); // Large industrial networks
            } catch (NumberFormatException e) {
                return false;
            }
        }
        
        return false;
    }

    /**
     * Clear detected assets tracking (useful for new analysis sessions)
     */
    public void clearDetectedAssetsTracking() {
        detectedIpAddresses.clear();
        detectedMacAddresses.clear();
        detectedHostnames.clear();
        logger.info("Cleared detected assets tracking");
    }
} 