package com.safetech.otshield.service;

import com.safetech.otshield.model.HoneypotLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class ConpotLogIntegrationService {
    
    private static final Logger logger = LoggerFactory.getLogger(ConpotLogIntegrationService.class);
    
    @Autowired
    private HoneypotLogService honeypotLogService;
    
    private final Path conpotLogPath = Paths.get("conpot", "conpot.log");
    private long lastProcessedPosition = 0;

    /** When runtime is "remote" (Conpot lives on a separate host and ships logs
     *  via /api/honeypot/ingest) the local disk-file watcher is disabled. */
    @Value("${conpot.runtime:docker}")
    private String runtime;
    private final Pattern connectionPattern = Pattern.compile("New (\\w+) connection from (\\d+\\.\\d+\\.\\d+\\.\\d+):(\\d+)\\. \\(([a-f0-9-]+)\\)");
    private final Pattern resetPattern = Pattern.compile("Connection reset by peer, remote: (\\d+\\.\\d+\\.\\d+\\.\\d+)\\. \\(([a-f0-9-]+)\\)");
    // Credential patterns — Conpot's HTTP template logs basic-auth attempts and the SSH template logs username/password
    private final Pattern httpAuthPattern = Pattern.compile("Authorization:\\s*Basic\\s+([A-Za-z0-9+/=]+)", Pattern.CASE_INSENSITIVE);
    private final Pattern loginPattern = Pattern.compile("(?:login|user(?:name)?)[=:\\s]+['\"]?([\\w.@-]{1,64})['\"]?", Pattern.CASE_INSENSITIVE);
    private final Pattern passwordPattern = Pattern.compile("(?:pass(?:word|wd)?)[=:\\s]+['\"]?([^\\s'\"&]{1,64})['\"]?", Pattern.CASE_INSENSITIVE);
    private final Pattern sshCredPattern = Pattern.compile("(?:authentication attempt|login attempt)\\s+(?:for|from)?\\s*\\[?([\\w.@-]{1,64})\\]?.*?(?:password|passwd)[=:\\s]+['\"]?([^\\s'\"]{1,64})", Pattern.CASE_INSENSITIVE);
    private final Pattern userAgentPattern = Pattern.compile("User-Agent:\\s*([^\\r\\n]+)", Pattern.CASE_INSENSITIVE);
    
    @Scheduled(fixedRate = 5000) // Her 5 saniyede bir kontrol et
    public void processConpotLogs() {
        // In remote mode, logs arrive via the /api/honeypot/ingest endpoint
        // (see HoneypotController) — there is no local disk file to watch.
        if ("remote".equalsIgnoreCase(runtime)) {
            return;
        }
        if (!Files.exists(conpotLogPath)) {
            logger.debug("Conpot log file not found: {}", conpotLogPath);
            return;
        }
        
        try {
            long currentSize = Files.size(conpotLogPath);
            if (currentSize <= lastProcessedPosition) {
                return; // Yeni log yok
            }
            
            List<String> newLines = readNewLines();
            if (!newLines.isEmpty()) {
                processNewLogLines(newLines);
                lastProcessedPosition = currentSize;
            }
            
        } catch (IOException e) {
            logger.error("Error processing Conpot logs", e);
        }
    }
    
    private List<String> readNewLines() throws IOException {
        List<String> newLines = new ArrayList<>();
        
        try (BufferedReader reader = new BufferedReader(new FileReader(conpotLogPath.toFile()))) {
            String line;
            long lineCount = 0;
            
            while ((line = reader.readLine()) != null) {
                lineCount++;
                if (lineCount > lastProcessedPosition) {
                    newLines.add(line);
                }
            }
        }
        
        return newLines;
    }
    
    private void processNewLogLines(List<String> lines) {
        for (String line : lines) {
            try {
                processLogLine(line);
            } catch (Exception e) {
                logger.warn("Error processing log line: {}", line, e);
            }
        }
    }
    
    /**
     * Parse a single Conpot log line and persist a HoneypotLog row for it.
     * Public so ConpotService.addLog() can reuse the same parser for its
     * in-memory simulation logs (which never hit the disk file watcher).
     */
    public void processLogLine(String line) {
        logger.info("[parser] processing line: {}", line);
        // Yeni bağlantı tespit et
        Matcher connectionMatcher = connectionPattern.matcher(line);
        if (connectionMatcher.find()) {
            String protocol = connectionMatcher.group(1);
            String sourceIp = connectionMatcher.group(2);
            String sourcePort = connectionMatcher.group(3);
            String sessionId = connectionMatcher.group(4);

            logger.info("[parser] connectionPattern matched: protocol={}, ip={}, port={}, session={}",
                protocol, sourceIp, sourcePort, sessionId);
            createHoneypotLog(protocol, sourceIp, sourcePort, "Connection Established", "LOW", sessionId, null, null, null);
            return;
        }

        // Bağlantı reset tespit et
        Matcher resetMatcher = resetPattern.matcher(line);
        if (resetMatcher.find()) {
            String sourceIp = resetMatcher.group(1);
            String sessionId = resetMatcher.group(2);

            createHoneypotLog("Unknown", sourceIp, "0", "Connection Reset", "LOW", sessionId, null, null, null);
            return;
        }

        // Credential capture (HTTP Basic, SSH/Telnet login attempts, form-encoded logins)
        String username = null, password = null, userAgent = null;

        Matcher sshCred = sshCredPattern.matcher(line);
        if (sshCred.find()) {
            username = sshCred.group(1);
            password = sshCred.group(2);
        } else {
            Matcher loginM = loginPattern.matcher(line);
            if (loginM.find()) username = loginM.group(1);
            Matcher pwM = passwordPattern.matcher(line);
            if (pwM.find()) password = pwM.group(1);
        }

        Matcher httpAuth = httpAuthPattern.matcher(line);
        if (httpAuth.find()) {
            try {
                String decoded = new String(java.util.Base64.getDecoder().decode(httpAuth.group(1)));
                int idx = decoded.indexOf(':');
                if (idx > 0) {
                    if (username == null) username = decoded.substring(0, Math.min(idx, 64));
                    if (password == null) password = decoded.substring(idx + 1, Math.min(idx + 1 + 64, decoded.length()));
                }
            } catch (Exception ignored) {}
        }

        Matcher uaM = userAgentPattern.matcher(line);
        if (uaM.find()) userAgent = uaM.group(1).trim();

        // Modbus — match many possible Conpot output shapes:
        //   "Modbus traffic from 1.2.3.4: {'function_code': 3, ...}"
        //   "Modbus request from 1.2.3.4: ..."
        //   "Modbus client provided data ... but invalid"
        //   "Modbus exception ..."
        if (line.contains("Modbus") || line.contains("modbus")) {
            String sourceIp = extractIpFromLine(line);
            if (sourceIp != null) {
                String attackType = extractModbusAttackType(line);
                String severity = "MEDIUM";
                if (line.toLowerCase().contains("invalid") || line.toLowerCase().contains("exception")
                        || line.toLowerCase().contains("illegal")) {
                    severity = "HIGH";
                    if (attackType.equals("Modbus Request")) attackType = "Modbus Exception";
                }
                // Extract the function code from any common form so the dashboard's
                // FC chart picks it up. Conpot dumps "'function_code': N" — we
                // canonicalise it to "function code N" for downstream parsers.
                Integer fc = extractModbusFunctionCode(line);
                String desc = "Modbus traffic from " + sourceIp;
                if (fc != null) {
                    desc += " · function code " + fc;
                    attackType = enrichModbusAttackType(attackType, fc);
                    if (isWriteFc(fc)) severity = "HIGH";
                }
                createModbusLog(sourceIp, attackType, severity, desc, userAgent);
            }
            return;
        }

        // S7Comm — same broad keyword match
        if (line.contains("S7") || line.contains("s7comm") || line.contains("S7Comm")) {
            String sourceIp = extractIpFromLine(line);
            if (sourceIp != null) {
                createHoneypotLog("S7COMM", sourceIp, "10201", "S7 Request", "MEDIUM", null, null, null, userAgent);
            }
            return;
        }

        // HTTP — extract method + path, set description so the dashboard
        // can render method/path breakdown.
        if (line.contains("HTTP") || line.contains("http")
            || line.contains("GET ") || line.contains("POST ")
            || line.contains("PUT ") || line.contains("DELETE ")
            || line.contains("HEAD ") || line.contains("OPTIONS ")) {
            String sourceIp = extractIpFromLine(line);
            if (sourceIp != null) {
                // Pull method + path from anywhere in the line.
                java.util.regex.Matcher mp = java.util.regex.Pattern
                    .compile("\\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\\b\\s+(\\S+)")
                    .matcher(line);
                String method = null, path = null;
                if (mp.find()) {
                    method = mp.group(1);
                    path = mp.group(2);
                    // Strip Conpot-style trailing punctuation like "POST /admin." or "POST /admin'"
                    if (path != null) {
                        path = path.replaceAll("['\",.;)]+$", "");
                    }
                }

                String sev = "LOW";
                String type = "HTTP Request";
                if (username != null || password != null) {
                    sev = "MEDIUM";
                    type = "HTTP Login Attempt";
                }
                if (line.toLowerCase().contains("brute") || line.toLowerCase().contains("dictionary")) {
                    sev = "HIGH";
                    type = "HTTP Brute Force";
                }

                // Build a description that getStatistics can parse for method+path
                StringBuilder desc = new StringBuilder("HTTP traffic from ").append(sourceIp);
                if (method != null) desc.append(" · ").append(method);
                if (path != null) desc.append(" ").append(path);

                createHttpLog(sourceIp, type, sev, desc.toString(), username, password, userAgent);
            }
            return;
        }

        // IEC 60870-5-104 — common in power grid SCADA. Conpot's iec104
        // template emits "IEC104 ..." or "iec104 ..." style log lines.
        if (line.toLowerCase().contains("iec104") || line.toLowerCase().contains("iec 104")
            || line.contains("STARTDT") || line.contains("STOPDT") || line.contains("TESTFR")
            || line.contains("C_IC_NA") || line.contains("C_SC_NA") || line.contains("C_DC_NA")
            || line.contains("ASDU")) {
            String sourceIp = extractIpFromLine(line);
            if (sourceIp != null) {
                String type = "IEC104 Request";
                String sev = "MEDIUM";
                if (line.contains("C_SC_NA") || line.contains("C_DC_NA") || line.contains("C_RC_NA")
                    || line.contains("C_SE_NA") || line.contains("C_BO_NA")) {
                    type = "IEC104 Control Command";
                    sev = "HIGH";
                } else if (line.contains("C_IC_NA")) {
                    type = "IEC104 General Interrogation";
                    sev = "MEDIUM";
                } else if (line.contains("STARTDT") || line.contains("STOPDT")) {
                    type = "IEC104 Session Control";
                    sev = "LOW";
                } else if (line.contains("TESTFR")) {
                    type = "IEC104 Test Frame";
                    sev = "LOW";
                }
                createIec104Log(sourceIp, type, sev, "IEC104 traffic from " + sourceIp + " · " + type, userAgent);
            }
            return;
        }

        // Fallback — if we still captured credentials but no protocol keyword matched
        if (username != null || password != null) {
            String sourceIp = extractIpFromLine(line);
            if (sourceIp != null) {
                createHoneypotLog("Unknown", sourceIp, "0", "Login Attempt", "MEDIUM", null, username, password, userAgent);
            }
        }
    }

    /** IEC 60870-5-104 specific persist (port 2404, ICS power grid protocol). */
    private void createIec104Log(String sourceIp, String attackType, String severity, String description, String userAgent) {
        try {
            HoneypotLog log = new HoneypotLog();
            log.setSourceIp(sourceIp);
            log.setProtocol("IEC104");
            log.setAttackType(attackType);
            log.setSeverity(severity);
            log.setDescription(description);
            log.setTimestamp(LocalDateTime.now());
            log.setDestinationPort(2404);
            log.setUserAgent(userAgent);
            log.setIsBlocked(false);
            honeypotLogService.saveLog(log);
            logger.debug("IEC104 log: ip={}, type={}, sev={}", sourceIp, attackType, severity);
        } catch (Exception e) {
            logger.error("[parser] FAILED createIec104Log for ip=" + sourceIp, e);
        }
    }
    
    private String extractIpFromLine(String line) {
        Pattern ipPattern = Pattern.compile("(\\d+\\.\\d+\\.\\d+\\.\\d+)");
        Matcher matcher = ipPattern.matcher(line);
        return matcher.find() ? matcher.group(1) : null;
    }
    
    private String extractModbusAttackType(String line) {
        if (line.contains("read")) return "Modbus Read";
        if (line.contains("write")) return "Modbus Write";
        if (line.contains("scan")) return "Modbus Scan";
        if (line.contains("brute force")) return "Modbus Brute Force";
        return "Modbus Request";
    }

    /**
     * Pull the Modbus function code from any common Conpot log form:
     *   "function code 3"          - our enriched description
     *   "function_code 3"          - alt form
     *   "'function_code': 3"       - Conpot's dict dump
     *   "function code: 3"         - variant
     */
    private Integer extractModbusFunctionCode(String line) {
        java.util.regex.Matcher m = java.util.regex.Pattern
            .compile("function[\\s_]?code['\":\\s]+(\\d+)", java.util.regex.Pattern.CASE_INSENSITIVE)
            .matcher(line);
        if (m.find()) {
            try { return Integer.parseInt(m.group(1)); } catch (NumberFormatException ignored) {}
        }
        return null;
    }

    /** Map Modbus FC numbers to human-readable attack types. */
    private String enrichModbusAttackType(String fallback, int fc) {
        switch (fc) {
            case 1:  return "Modbus Read Coils";
            case 2:  return "Modbus Read Discrete Inputs";
            case 3:  return "Modbus Read Holding Registers";
            case 4:  return "Modbus Read Input Registers";
            case 5:  return "Modbus Write Single Coil";
            case 6:  return "Modbus Write Single Register";
            case 8:  return "Modbus Diagnostics";
            case 15: return "Modbus Write Multiple Coils";
            case 16: return "Modbus Write Multiple Registers";
            case 17: return "Modbus Report Slave ID";
            case 20: return "Modbus Read File Record";
            case 21: return "Modbus Write File Record";
            case 22: return "Modbus Mask Write Register";
            case 23: return "Modbus Read/Write Multiple";
            case 43: return "Modbus Encapsulated Interface";
            default: return fallback;
        }
    }

    private boolean isWriteFc(int fc) {
        return fc == 5 || fc == 6 || fc == 15 || fc == 16 || fc == 22 || fc == 23 || fc == 21;
    }

    /** HTTP-specific create that stores method+path in description for downstream stats. */
    private void createHttpLog(String sourceIp, String attackType, String severity, String description,
                                String usernameAttempt, String passwordAttempt, String userAgent) {
        try {
            HoneypotLog log = new HoneypotLog();
            log.setSourceIp(sourceIp);
            log.setProtocol("HTTP");
            log.setAttackType(attackType);
            log.setSeverity(severity);
            log.setDescription(description);
            log.setTimestamp(LocalDateTime.now());
            log.setDestinationPort(80);
            log.setUsernameAttempt(usernameAttempt);
            log.setPasswordAttempt(passwordAttempt);
            log.setUserAgent(userAgent);
            log.setIsBlocked(false);
            honeypotLogService.saveLog(log);
            logger.debug("HTTP log: ip={}, type={}, sev={}, desc={}", sourceIp, attackType, severity, description);
        } catch (Exception e) {
            logger.error("[parser] FAILED createHttpLog for ip=" + sourceIp, e);
        }
    }

    /** Modbus-specific create that also stores the function code in description for downstream stats. */
    private void createModbusLog(String sourceIp, String attackType, String severity, String description, String userAgent) {
        try {
            HoneypotLog log = new HoneypotLog();
            log.setSourceIp(sourceIp);
            log.setProtocol("MODBUS");
            log.setAttackType(attackType);
            log.setSeverity(severity);
            log.setDescription(description);
            log.setTimestamp(LocalDateTime.now());
            log.setDestinationPort(502);
            log.setUserAgent(userAgent);
            log.setIsBlocked(false);
            honeypotLogService.saveLog(log);
            logger.debug("Modbus log: ip={}, type={}, sev={}, desc={}", sourceIp, attackType, severity, description);
        } catch (Exception e) {
            logger.error("[parser] FAILED createModbusLog for ip=" + sourceIp, e);
        }
    }
    
    private void createHoneypotLog(String protocol, String sourceIp, String sourcePort, String attackType, String severity,
                                    String sessionId, String usernameAttempt, String passwordAttempt, String userAgent) {
        // Normalize protocol so 'Modbus' and 'MODBUS' don't show up as two
        // separate buckets in Protocol Distribution. Also fixes 'modbus',
        // 's7comm', etc. coming from raw Conpot lines.
        protocol = normalizeProtocol(protocol);

        logger.info("[parser] createHoneypotLog ENTER: protocol={}, ip={}, port={}, type={}",
            protocol, sourceIp, sourcePort, attackType);
        try {
            HoneypotLog log = new HoneypotLog();
            log.setSourceIp(sourceIp);
            try {
                log.setSourcePort(Integer.parseInt(sourcePort));
            } catch (NumberFormatException ignored) { /* keep null */ }
            log.setProtocol(protocol);
            log.setAttackType(attackType);
            log.setSeverity(severity);
            log.setTimestamp(LocalDateTime.now());
            log.setSessionId(sessionId);
            log.setUsernameAttempt(usernameAttempt);
            log.setPasswordAttempt(passwordAttempt);
            log.setUserAgent(userAgent);
            log.setIsBlocked(false);

            // Map Conpot container ports -> service port for analytics
            Integer dstPort = inferDestinationPort(protocol);
            if (dstPort != null) log.setDestinationPort(dstPort);

            // Geolocation is enriched by HoneypotLogService.saveLog()
            HoneypotLog saved = honeypotLogService.saveLog(log);
            logger.info("[parser] saved honeypot log id={} from {} ({})",
                saved.getId(), sourceIp, protocol);

        } catch (Exception e) {
            logger.error("[parser] FAILED createHoneypotLog for ip=" + sourceIp, e);
        }
    }

    private static Integer inferDestinationPort(String protocol) {
        if (protocol == null) return null;
        switch (protocol.toUpperCase()) {
            case "MODBUS": return 502;
            case "S7COMM": case "S7": return 102;
            case "SNMP": return 161;
            case "HTTP": return 80;
            case "BACNET": return 47808;
            case "DNP3": return 20000;
            case "ETHERNETIP": case "ETHERNET/IP": return 44818;
            case "IEC104": case "IEC 104": case "IEC-104": return 2404;
            default: return null;
        }
    }

    /**
     * Canonicalise protocol names so case / spelling variants from raw Conpot
     * log lines collapse into a single bucket on the dashboard. Examples:
     *   "modbus" / "Modbus" / "MODBUS" -> "MODBUS"
     *   "s7"     / "S7Comm" / "s7comm" -> "S7COMM"
     *   "http"   / "Http"   / "HTTP"   -> "HTTP"
     */
    private static String normalizeProtocol(String protocol) {
        if (protocol == null || protocol.isBlank()) return "UNKNOWN";
        String p = protocol.trim().toUpperCase();
        switch (p) {
            case "MODBUS": return "MODBUS";
            case "S7": case "S7COMM": return "S7COMM";
            case "HTTP": case "HTTPS": return "HTTP";
            case "SNMP": return "SNMP";
            case "BACNET": return "BACNET";
            case "DNP3": return "DNP3";
            case "ETHERNETIP": case "ETHERNET/IP": case "ENIP": return "ENIP";
            case "IEC104": case "IEC 104": case "IEC-104": return "IEC104";
            case "IPMI": return "IPMI";
            case "FTP": return "FTP";
            case "TFTP": return "TFTP";
            case "KAMSTRUP": return "KAMSTRUP";
            case "GUARDIAN": case "GUARDIAN-AST": return "GUARDIAN-AST";
            case "UNKNOWN": return "UNKNOWN";
            default: return p;
        }
    }
    
    public void resetLogPosition() {
        lastProcessedPosition = 0;
        logger.info("Reset Conpot log integration position");
    }
    
    public long getLastProcessedPosition() {
        return lastProcessedPosition;
    }
}
