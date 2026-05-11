package com.safetech.otshield.service;

import com.safetech.otshield.event.ConpotStatusEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;

import jakarta.annotation.PreDestroy;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.net.Socket;
import java.net.InetSocketAddress;

@Service
public class ConpotService {
    
    private static final Logger logger = LoggerFactory.getLogger(ConpotService.class);
    
    private Process conpotProcess;
    private boolean isRunning = false;
    private final List<String> logs = new ArrayList<>();
    private ScheduledExecutorService scheduler;
    private final Path logDirectory = Paths.get("conpot_logs");
    /** Last error message when start failed; cleared on success. */
    private volatile String lastStartError = null;

    /** Optional: full path to Python executable if not in PATH (e.g. C:\\Python311\\python.exe). */
    @Value("${conpot.python.path:}")
    private String configuredPythonPath;
    /** Runtime for Conpot: "docker" (preferred, uses honeynet/conpot image) or "python" (subprocess). */
    @Value("${conpot.runtime:docker}")
    private String runtime;
    /** Docker image tag for Conpot. */
    @Value("${conpot.docker.image:honeynet/conpot:latest}")
    private String dockerImage;
    /** Name of the running Conpot container (so we can stop it). */
    @Value("${conpot.docker.container-name:otshield-conpot}")
    private String dockerContainerName;
    /** Optional: explicit path to docker CLI. Leave blank to rely on PATH. */
    @Value("${conpot.docker.path:}")
    private String dockerPath;
    
    @Autowired
    private ApplicationEventPublisher eventPublisher;
    
    @Autowired
    private HoneypotLogService honeypotLogService;

    @Autowired
    private ConpotLogIntegrationService conpotLogIntegrationService;

    @Autowired
    private com.safetech.otshield.repository.HoneypotLogRepository honeypotLogRepository;
    
    public ConpotService() {
        try {
            Files.createDirectories(logDirectory);
            
            // Create required directories for conpot
            String currentDir = System.getProperty("user.dir");
            String projectDir;
            
            // If we're in backend directory, go up one level to find project root
            if (currentDir.endsWith("backend")) {
                projectDir = currentDir + "/..";
            } else {
                projectDir = currentDir;
            }
            
            Path testsDataDir = Paths.get(projectDir, "tests", "data", "data_temp_fs");
            Files.createDirectories(testsDataDir);
            
            logger.info("Created required directories for Conpot");
        } catch (IOException e) {
            logger.error("Failed to create required directories", e);
        }
    }
    
    public String getLastStartError() {
        return lastStartError;
    }

    public boolean isRemoteMode() {
        return "remote".equalsIgnoreCase(runtime);
    }

    public String getRuntime() {
        return runtime;
    }

    public boolean startConpot() {
        lastStartError = null;
        if (isRunning) {
            logger.warn("Conpot is already running");
            lastStartError = "Conpot is already running.";
            return false;
        }

        // Remote runtime: Conpot runs on a separate host (e.g. GCP VM) and ships
        // logs via /api/honeypot/ingest. Nothing to start locally.
        if ("remote".equalsIgnoreCase(runtime)) {
            lastStartError = "Conpot is configured as remote. Logs are ingested from /api/honeypot/ingest. No local container is started.";
            logger.info(lastStartError);
            return false;
        }

        try {
            // Prefer Docker runtime when configured (default)
            if ("docker".equalsIgnoreCase(runtime)) {
                String dockerCmd = findDockerCommand();
                if (dockerCmd == null) {
                    lastStartError = "Docker not found. Install Docker Desktop and ensure 'docker' is on PATH, or set conpot.docker.path in application.properties.";
                    logger.error(lastStartError);
                    return false;
                }
                return startConpotWithDocker(dockerCmd);
            }

            // Legacy Python runtime path
            String pythonCommand = findPythonCommand();
            if (pythonCommand == null) {
                lastStartError = "Python not found. Install Python and add it to PATH, then run: pip install conpot";
                logger.error("No Python found: {}", lastStartError);
                return false;
            }
            boolean success = startConpotWithPython(pythonCommand);
            if (!success && lastStartError == null) {
                lastStartError = "Conpot process failed to start. Check backend logs.";
            }
            return success;
        } catch (Exception e) {
            lastStartError = "Error: " + e.getMessage();
            logger.error("Failed to start Conpot: {}", e.getMessage());
            return false;
        }
    }

    /** Find docker executable. Honors conpot.docker.path, otherwise relies on PATH. */
    private String findDockerCommand() {
        if (dockerPath != null && !dockerPath.isBlank()) {
            File f = new File(dockerPath.trim());
            if (f.isFile() && checkDockerExecutable(f.getAbsolutePath())) {
                return f.getAbsolutePath();
            }
        }
        // Try plain 'docker' on PATH
        if (checkDockerExecutable("docker")) {
            return "docker";
        }
        return null;
    }

    private boolean checkDockerExecutable(String cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd, "version", "--format", "{{.Server.Version}}");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                while (r.readLine() != null) { /* drain */ }
            }
            boolean completed = p.waitFor(5, TimeUnit.SECONDS);
            if (completed && p.exitValue() == 0) {
                logger.info("Docker engine reachable via: {}", cmd);
                return true;
            }
            logger.warn("Docker CLI '{}' present but engine not reachable (is Docker Desktop running?)", cmd);
            return false;
        } catch (Exception e) {
            logger.debug("Docker check failed for '{}': {}", cmd, e.getMessage());
            return false;
        }
    }

    /**
     * Start Conpot inside a Docker container using the honeynet/conpot image.
     * Maps ICS ports and streams container stdout/stderr into the logs list.
     */
    private boolean startConpotWithDocker(String dockerCmd) {
        try {
            // Stop/remove any leftover container with the same name
            removeDockerContainerQuietly(dockerCmd);

            logger.info("Starting Conpot Docker container '{}' from image '{}'", dockerContainerName, dockerImage);

            // Pull image up-front so error is visible to the user (quick no-op if already present)
            try {
                ProcessBuilder pullPb = new ProcessBuilder(dockerCmd, "pull", dockerImage);
                pullPb.redirectErrorStream(true);
                Process pull = pullPb.start();
                try (BufferedReader r = new BufferedReader(new InputStreamReader(pull.getInputStream()))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        logger.debug("docker pull: {}", line);
                    }
                }
                pull.waitFor(120, TimeUnit.SECONDS);
            } catch (Exception pullEx) {
                logger.warn("docker pull failed (will still try to run if image is cached): {}", pullEx.getMessage());
            }

            // Run container in foreground so we can stream its logs; --rm removes it when stopped
            // honeynet/conpot:latest default template listens on these CONTAINER ports
            // (observed from `docker logs` startup output):
            //   Modbus:      5020/tcp
            //   S7Comm:      10201/tcp
            //   HTTP:        8800/tcp
            //   SNMP:        16100/udp
            //   BACnet:      47808/udp
            //   IPMI:        6230/tcp
            //   EtherNet/IP: 44818/tcp
            //   FTP:         2121/tcp
            //   TFTP:        6969/udp
            // We map host:container 1:1 so the typical host-side ports stay predictable.
            List<String> cmd = new ArrayList<>();
            cmd.add(dockerCmd);
            cmd.add("run");
            cmd.add("--rm");
            cmd.add("--name"); cmd.add(dockerContainerName);
            cmd.add("-p"); cmd.add("5020:5020");         // Modbus
            cmd.add("-p"); cmd.add("10201:10201");       // S7Comm
            cmd.add("-p"); cmd.add("8800:8800");         // HTTP
            cmd.add("-p"); cmd.add("16100:16100/udp");   // SNMP
            cmd.add("-p"); cmd.add("47808:47808/udp");   // BACnet
            cmd.add("-p"); cmd.add("6230:6230");         // IPMI
            cmd.add("-p"); cmd.add("44818:44818");       // EtherNet/IP
            cmd.add("-p"); cmd.add("2121:2121");         // FTP
            cmd.add("-p"); cmd.add("6969:6969/udp");     // TFTP
            cmd.add(dockerImage);

            ProcessBuilder runPb = new ProcessBuilder(cmd);
            runPb.redirectErrorStream(true);
            conpotProcess = runPb.start();
            logger.info("docker run started (PID {})", conpotProcess.pid());

            // Give the container 3s to surface early failures (port conflict, missing image, etc.)
            Thread.sleep(3000);
            if (!conpotProcess.isAlive()) {
                int exitCode = conpotProcess.exitValue();
                StringBuilder err = new StringBuilder();
                try (BufferedReader r = new BufferedReader(new InputStreamReader(conpotProcess.getInputStream()))) {
                    String line;
                    while ((line = r.readLine()) != null) {
                        logger.error("conpot container output: {}", line);
                        if (err.length() > 0) err.append(" ");
                        err.append(line.trim());
                    }
                } catch (IOException ignored) {}
                if (err.length() > 200) err.setLength(200);
                lastStartError = err.length() > 0
                    ? "Conpot container exited (code " + exitCode + "): " + err
                    : "Conpot container exited with code " + exitCode + ". Check Docker Desktop is running and ports are free.";
                return false;
            }

            // Stream container stdout into the logs list
            startLogMonitoring();
            isRunning = true;
            logger.info("Conpot Docker container '{}' is running", dockerContainerName);
            return true;
        } catch (Exception e) {
            lastStartError = "Docker start error: " + e.getMessage();
            logger.error("Failed to start Conpot via Docker: {}", e.getMessage(), e);
            return false;
        }
    }

    private void removeDockerContainerQuietly(String dockerCmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(dockerCmd, "rm", "-f", dockerContainerName);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                while (r.readLine() != null) { /* drain */ }
            }
            p.waitFor(10, TimeUnit.SECONDS);
        } catch (Exception e) {
            logger.debug("No leftover container to remove (ok): {}", e.getMessage());
        }
    }
    
    private String findPythonCommand() {
        // If a path is configured (e.g. when Python is not in PATH for the Java process), try it first
        if (configuredPythonPath != null && !configuredPythonPath.isBlank()) {
            String path = configuredPythonPath.trim();
            File f = new File(path);
            if (f.isFile() && f.exists() && checkPythonExecutable(path)) {
                return path;
            }
            if (f.isDirectory()) {
                for (String name : new String[]{"python.exe", "python", "python3"}) {
                    File exe = new File(f, name);
                    if (exe.isFile() && exe.exists() && checkPythonExecutable(exe.getAbsolutePath())) {
                        return exe.getAbsolutePath();
                    }
                }
            } else if (checkPythonExecutable(path)) {
                return path;
            }
        }
        String[] commands = {"python", "python3", "py"};
        for (String cmd : commands) {
            try {
                ProcessBuilder pb = new ProcessBuilder(cmd, "--version");
                pb.redirectErrorStream(true);
                Process process = pb.start();
                
                // Read output to avoid hanging
                BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
                StringBuilder output = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\n");
                }
                
                boolean completed = process.waitFor(5, TimeUnit.SECONDS);
                if (completed && process.exitValue() == 0) {
                    logger.info("Found Python command: {} with version: {}", cmd, output.toString().trim());
                    return cmd;
                }
            } catch (Exception e) {
                logger.debug("Python command {} not found: {}", cmd, e.getMessage());
            }
        }
        logger.warn("No Python command found. Set conpot.python.path in application.properties to your Python executable.");
        return null;
    }

    private boolean checkPythonExecutable(String executablePath) {
        try {
            ProcessBuilder pb = new ProcessBuilder(executablePath, "--version");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                while (reader.readLine() != null) { }
            }
            boolean ok = process.waitFor(5, TimeUnit.SECONDS) && process.exitValue() == 0;
            if (ok) {
                logger.info("Using configured Python: {}", executablePath);
            }
            return ok;
        } catch (Exception e) {
            logger.debug("Configured Python path not usable: {} - {}", executablePath, e.getMessage());
            return false;
        }
    }
    
    private boolean startConpotWithPython(String pythonCommand) {
        try {
            logger.info("Attempting to start Conpot with Python command: {}", pythonCommand);
            
            String projectDir = System.getProperty("user.dir");
            File projectRootFile = new File(projectDir);
            if ("backend".equals(projectRootFile.getName())) {
                projectRootFile = projectRootFile.getParentFile();
            }
            String projectRoot = projectRootFile != null ? projectRootFile.getAbsolutePath() : projectDir;
            String conpotDir = projectRoot + File.separator + "conpot";
            File conpotDirectory = new File(conpotDir);
            File conpotExecutable = new File(conpotDirectory, "bin" + File.separator + "conpot");
            
            ProcessBuilder startPb;
            File workingDir;
            
            if (conpotDirectory.exists() && conpotExecutable.exists()) {
                // Run from cloned Conpot repo
                logger.info("Starting Conpot from directory: {}", conpotDir);
                startPb = new ProcessBuilder(
                    pythonCommand, "bin/conpot", "-f", "-v", "--template", "default", "--logfile", "conpot.log"
                );
                Map<String, String> env = startPb.environment();
                String currentPath = env.getOrDefault("PYTHONPATH", "");
                String newPath = conpotDir + File.pathSeparator + currentPath;
                env.put("PYTHONPATH", newPath);
                env.put("PYTHONIOENCODING", "utf-8");
                startPb.directory(conpotDirectory);
                workingDir = conpotDirectory;
            } else {
                // Run via pip-installed conpot (python -m conpot)
                logger.info("Conpot directory not found at {}, trying pip-installed conpot (python -m conpot)", conpotDir);
                workingDir = logDirectory.toFile();
                if (!workingDir.exists()) {
                    workingDir.mkdirs();
                }
                startPb = new ProcessBuilder(
                    pythonCommand, "-m", "conpot", "-f", "-v", "--template", "default", "--logfile", "conpot.log"
                );
                startPb.environment().put("PYTHONIOENCODING", "utf-8");
                startPb.directory(workingDir);
            }
            
            startPb.redirectErrorStream(true);
            conpotProcess = startPb.start();
            logger.info("Conpot process started with PID: {}", conpotProcess.pid());
            
            // Read initial output to check for errors
            Thread.sleep(2000);
            if (!conpotProcess.isAlive()) {
                int exitCode = conpotProcess.exitValue();
                logger.error("Conpot process died immediately. Exit code: {}", exitCode);
                StringBuilder err = new StringBuilder();
                try (BufferedReader reader = new BufferedReader(new InputStreamReader(conpotProcess.getInputStream()))) {
                    String line;
                    while ((line = reader.readLine()) != null) {
                        logger.error("Conpot output: {}", line);
                        if (err.length() > 0) err.append(" ");
                        err.append(line.trim());
                    }
                } catch (IOException e) {
                    logger.debug("Could not read process output: {}", e.getMessage());
                }
                if (err.length() > 200) err.setLength(200);
                lastStartError = err.length() > 0
                    ? "Conpot exited (code " + exitCode + "): " + err.toString()
                    : "Conpot exited with code " + exitCode + ". Run 'pip install conpot' if not installed.";
                return false;
            }
            
            // Wait a moment for Conpot to start and check if ports are open
            Thread.sleep(3000);
            boolean portsOpen = checkConpotPorts();
            if (!portsOpen) {
                logger.warn("Conpot started but ports are not accessible. This might be a firewall or permission issue.");
                logger.info("Process is still alive: {}", conpotProcess.isAlive());
            }
            
            // Start log monitoring
            startLogMonitoring();
            isRunning = true;
            logger.info("Conpot started successfully from directory: {}", workingDir.getAbsolutePath());
            return true;
            
        } catch (Exception e) {
            lastStartError = "Error: " + e.getMessage();
            logger.error("Failed to start Conpot with Python: {}", e.getMessage(), e);
            return false;
        }
    }
    
    private boolean checkConpotPorts() {
        int[] ports = {5020, 8800, 10201, 6230, 44818};
        int openPorts = 0;
        
        for (int port : ports) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress("localhost", port), 1000);
                openPorts++;
                logger.info("Port {} is open", port);
            } catch (Exception e) {
                logger.warn("Port {} is not accessible: {}", port, e.getMessage());
            }
        }
        
        logger.info("Found {} open ports out of {} expected", openPorts, ports.length);
        return openPorts > 0;
    }
    
    private void startLogMonitoring() {
        // Create new scheduler if needed
        if (scheduler == null || scheduler.isShutdown()) {
            scheduler = Executors.newScheduledThreadPool(1);
        }
        
        // Reset log integration position when starting
        conpotLogIntegrationService.resetLogPosition();
        
        scheduler.schedule(() -> {
            if (conpotProcess != null && conpotProcess.isAlive()) {
                try {
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(conpotProcess.getInputStream())
                    );
                    String line;
                    while ((line = reader.readLine()) != null) {
                        addLog(line);
                    }
                } catch (IOException e) {
                    logger.error("Error reading Conpot logs", e);
                }
            }
        }, 0, TimeUnit.SECONDS);
    }
    
    /**
     * Append a single Conpot log line to the in-memory ring buffer ONLY,
     * without invoking the parser. Used by HoneypotController.ingestLogs()
     * after the line has already been parsed and persisted, so the WebSocket
     * Live Stream picks it up without producing a duplicate DB row.
     */
    public void appendLineForStreamOnly(String log) {
        if (log == null || log.isBlank()) return;
        synchronized (logs) {
            logs.add(log);
            if (logs.size() > 1000) {
                logs.remove(0);
            }
        }
        try {
            eventPublisher.publishEvent(new ConpotStatusEvent(this));
        } catch (Exception ignored) { /* WebSocket throttling is best-effort */ }
    }

    private void addLog(String log) {
        synchronized (logs) {
            logs.add(log);
            logger.debug("Added log: {} (Total logs: {})", log, logs.size());
            // Keep only last 1000 logs
            if (logs.size() > 1000) {
                logs.remove(0);
            }
        }

        // Push this log line into the persistence pipeline so Attack Intelligence
        // sees it. ConpotLogIntegrationService tails the disk file on a 5s
        // schedule, but invoking the parser directly here ensures lines streamed
        // from the container's stdout are persisted without waiting for the file
        // tail to catch up.
        try {
            conpotLogIntegrationService.processLogLine(log);
        } catch (Exception e) {
            logger.debug("processLogLine failed for '{}': {}", log, e.getMessage());
        }

        // Publish event for status update - but throttle to avoid WebSocket issues
        try {
            eventPublisher.publishEvent(new ConpotStatusEvent(this));
        } catch (Exception e) {
            logger.debug("Failed to publish Conpot status event: {}", e.getMessage());
        }
    }
    
    private void parseAndSaveHoneypotLog(String logLine) {
        try {
            // Parse common Conpot log patterns
            if (logLine.contains("connection from")) {
                // Extract IP address from connection logs
                String[] parts = logLine.split("connection from");
                if (parts.length > 1) {
                    String ipPart = parts[1].trim().split("\\s+")[0];
                    String sourceIp = ipPart.split(":")[0];
                    
                    // Determine protocol from log content
                    String protocol = "UNKNOWN";
                    String attackType = "Connection Attempt";
                    String severity = "LOW";
                    
                    if (logLine.toLowerCase().contains("modbus")) {
                        protocol = "MODBUS";
                        attackType = "Modbus Connection";
                        severity = "MEDIUM";
                    } else if (logLine.toLowerCase().contains("http")) {
                        protocol = "HTTP";
                        attackType = "HTTP Request";
                        severity = "LOW";
                    } else if (logLine.toLowerCase().contains("s7comm")) {
                        protocol = "S7COMM";
                        attackType = "S7Comm Connection";
                        severity = "HIGH";
                    } else if (logLine.toLowerCase().contains("dnp3")) {
                        protocol = "DNP3";
                        attackType = "DNP3 Connection";
                        severity = "HIGH";
                    } else if (logLine.toLowerCase().contains("snmp")) {
                        protocol = "SNMP";
                        attackType = "SNMP Query";
                        severity = "MEDIUM";
                    }
                    
                    honeypotLogService.logAttack(sourceIp, protocol, attackType, logLine);
                }
            } else if (logLine.contains("attack") || logLine.contains("exploit") || logLine.contains("malicious")) {
                // Extract IP from attack logs
                String sourceIp = "UNKNOWN";
                String protocol = "UNKNOWN";
                String attackType = "Attack Detected";
                String severity = "HIGH";
                
                // Try to extract IP address
                String[] words = logLine.split("\\s+");
                for (String word : words) {
                    if (word.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
                        sourceIp = word;
                        break;
                    }
                }
                
                // Determine protocol and attack type
                if (logLine.toLowerCase().contains("modbus")) {
                    protocol = "MODBUS";
                    attackType = "Modbus Exploit";
                } else if (logLine.toLowerCase().contains("http")) {
                    protocol = "HTTP";
                    attackType = "HTTP Attack";
                } else if (logLine.toLowerCase().contains("s7comm")) {
                    protocol = "S7COMM";
                    attackType = "S7Comm Exploit";
                } else if (logLine.toLowerCase().contains("sql injection")) {
                    protocol = "HTTP";
                    attackType = "SQL Injection";
                    severity = "CRITICAL";
                } else if (logLine.toLowerCase().contains("xss")) {
                    protocol = "HTTP";
                    attackType = "XSS Attack";
                    severity = "CRITICAL";
                }
                
                honeypotLogService.logAttack(sourceIp, protocol, attackType, logLine);
            }
        } catch (Exception e) {
            logger.warn("Error parsing honeypot log: {}", e.getMessage());
        }
    }
    
    private String createWindowsConfig() {
        return """
            [common]
            sensorid = default
            
            [virtual_file_system]
            data_fs_url = default
            fs_url = default
            
            [session]
            timeout = 30
            
            [daemon]
            ; Windows doesn't support user/group daemon settings
            
            [json]
            enabled = False
            filename = conpot_logs/conpot.json
            
            [sqlite]
            enabled = False
            
            [syslog]
            enabled = False
            device = /dev/log
            host = localhost
            port = 514
            facility = local0
            socket = dev
            
            [hpfriends]
            enabled = False
            host = hpfriends.honeycloud.net
            port = 20000
            ident = 3Ykf9Znv
            secret = 4nFRhpm44QkG9cvD
            channels = ["conpot.events", ]
            
            [taxii]
            enabled = False
            host = taxiitest.mitre.org
            port = 80
            inbox_path = /services/inbox/default/
            use_https = False
            
            [fetch_public_ip]
            enabled = True
            urls = ["http://whatismyip.akamai.com/", "http://wgetip.com/"]
            """;
    }
    
    public boolean stopConpot() {
        if ("remote".equalsIgnoreCase(runtime)) {
            lastStartError = "Conpot is configured as remote. Stop the container on the remote host (e.g. docker stop otshield-conpot on the GCP VM).";
            logger.info(lastStartError);
            return false;
        }
        if (!isRunning) {
            logger.warn("Conpot is not running");
            return false;
        }

        try {
            // If we started a Docker container, stop it via the CLI so the
            // container exits cleanly (destroying the `docker run` java Process
            // alone isn't enough — dockerd keeps the container alive).
            if ("docker".equalsIgnoreCase(runtime)) {
                String dockerCmd = findDockerCommand();
                if (dockerCmd != null) {
                    try {
                        ProcessBuilder pb = new ProcessBuilder(dockerCmd, "stop", dockerContainerName);
                        pb.redirectErrorStream(true);
                        Process p = pb.start();
                        try (BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                            while (r.readLine() != null) { /* drain */ }
                        }
                        p.waitFor(15, TimeUnit.SECONDS);
                    } catch (Exception e) {
                        logger.warn("docker stop failed (will still destroy client process): {}", e.getMessage());
                    }
                }
            }

            if (conpotProcess != null && conpotProcess.isAlive()) {
                conpotProcess.destroy();
                conpotProcess.waitFor(5, TimeUnit.SECONDS);
                if (conpotProcess.isAlive()) {
                    conpotProcess.destroyForcibly();
                }
            }

            if (scheduler != null && !scheduler.isShutdown()) {
                scheduler.shutdown();
                try {
                    if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                        scheduler.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    scheduler.shutdownNow();
                    Thread.currentThread().interrupt();
                }
            }

            isRunning = false;
            logger.info("Conpot stopped successfully");
            return true;
        } catch (Exception e) {
            logger.error("Failed to stop Conpot", e);
            return false;
        }
    }
    
    public boolean isRunning() {
        return isRunning;
    }
    
    public List<String> getLogs() {
        synchronized (logs) {
            return new ArrayList<>(logs);
        }
    }
    
    public void clearLogs() {
        synchronized (logs) {
            logs.clear();
        }
    }
    
    /**
     * Per-Conpot-instance statistics, sourced from the persisted honeypot_logs
     * table. In remote mode the in-memory `logs` list is empty most of the
     * time (the sidecar POSTs straight into HoneypotLogService.saveLog), so
     * we read from the DB which is the single source of truth.
     *
     * Returns the same shape the Conpot Monitor frontend expects:
     *   totalConnections, uniqueIPs, uniqueSessions, modbusRequests,
     *   resetConnections, errorCount, totalLogs, isRunning,
     *   protocolBreakdown, severityBreakdown, modbusFunctionBreakdown,
     *   httpMethodBreakdown, httpPathBreakdown,
     *   topAttackers (list of {ip, attacks}),
     *   hourlySeries (24-bucket list of {hour, count}),
     *   recentEvents (last 50 events from DB).
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        // Apply the same internal-noise filter used by /api/honeypot/stats
        // and /api/honeypot/ttp-analysis so all three endpoints agree on
        // totals. Without this, RFC1918 / Docker bridge / loopback / null-IP
        // rows inflate the ICS Decoy Telemetry counters relative to the
        // Attack Intelligence and TTP Intel views.
        java.util.List<com.safetech.otshield.model.HoneypotLog> all =
            honeypotLogRepository.findAllByOrderByTimestampDesc().stream()
                .filter(l -> !HoneypotLogService.isInternalNoise(l))
                .collect(java.util.stream.Collectors.toList());

        int totalConnections = all.size();
        int resetCount = 0;
        int errorCount = 0;
        java.util.Set<String> ips = new java.util.HashSet<>();
        java.util.Set<String> sessions = new java.util.HashSet<>();
        Map<String, Integer> protocolCounts = new HashMap<>();
        Map<String, Integer> ipCounts = new HashMap<>();
        Map<String, Integer> modbusFunctionCounts = new HashMap<>();
        Map<String, Integer> httpMethodCounts = new HashMap<>();
        Map<String, Integer> httpPathCounts = new HashMap<>();
        Map<String, Integer> severityCounts = new HashMap<>();
        Map<Integer, Integer> hourlyBuckets = new HashMap<>();

        // Match all common Modbus function code formats:
        //   "function code 3"            (our enriched description)
        //   "function_code 3"            (alt form)
        //   "'function_code': 3"         (Conpot dict dump)
        //   "function code: 3"           (variant)
        java.util.regex.Pattern funcCodePattern =
            java.util.regex.Pattern.compile("function[\\s_]?code['\":\\s]+(\\d+)", java.util.regex.Pattern.CASE_INSENSITIVE);
        java.util.regex.Pattern httpMethodPattern =
            java.util.regex.Pattern.compile("\\b(GET|POST|PUT|DELETE|HEAD|OPTIONS)\\b\\s+(\\S+)");

        for (com.safetech.otshield.model.HoneypotLog row : all) {
            // IPs & sessions
            if (row.getSourceIp() != null) {
                ips.add(row.getSourceIp());
                ipCounts.merge(row.getSourceIp(), 1, Integer::sum);
            }
            if (row.getSessionId() != null && !row.getSessionId().isBlank()) {
                sessions.add(row.getSessionId());
            }

            // Protocol breakdown
            if (row.getProtocol() != null && !row.getProtocol().isBlank()) {
                protocolCounts.merge(row.getProtocol().toUpperCase(), 1, Integer::sum);
            }

            // Severity breakdown
            if (row.getSeverity() != null && !row.getSeverity().isBlank()) {
                severityCounts.merge(row.getSeverity().toUpperCase(), 1, Integer::sum);
            }

            // Resets / errors
            String typeLower = row.getAttackType() == null ? "" : row.getAttackType().toLowerCase();
            String descLower = row.getDescription() == null ? "" : row.getDescription().toLowerCase();
            if (typeLower.contains("reset") || descLower.contains("reset")) resetCount++;
            if (typeLower.contains("exception") || typeLower.contains("error")
                || descLower.contains("exception") || descLower.contains("illegal")) errorCount++;

            // Modbus function codes — pulled from description/payload if present
            String hay = (row.getDescription() == null ? "" : row.getDescription()) + " "
                       + (row.getPayload() == null ? "" : row.getPayload()) + " "
                       + (row.getAttackType() == null ? "" : row.getAttackType());
            java.util.regex.Matcher fm = funcCodePattern.matcher(hay);
            if (fm.find()) {
                modbusFunctionCounts.merge("FC " + fm.group(1), 1, Integer::sum);
            }

            // HTTP method + path
            if ("HTTP".equalsIgnoreCase(row.getProtocol())) {
                java.util.regex.Matcher hm = httpMethodPattern.matcher(hay);
                if (hm.find()) {
                    httpMethodCounts.merge(hm.group(1), 1, Integer::sum);
                    String path = hm.group(2);
                    if (path.length() > 60) path = path.substring(0, 60) + "...";
                    httpPathCounts.merge(path, 1, Integer::sum);
                }
            }

            // Hourly bucket from timestamp
            if (row.getTimestamp() != null) {
                int h = row.getTimestamp().getHour();
                hourlyBuckets.merge(h, 1, Integer::sum);
            }
        }

        // Top attackers (10) from ipCounts
        List<Map<String, Object>> topAttackers = ipCounts.entrySet().stream()
            .sorted((a, b) -> Integer.compare(b.getValue(), a.getValue()))
            .limit(10)
            .map(e -> {
                Map<String, Object> m = new HashMap<>();
                m.put("ip", e.getKey());
                m.put("attacks", e.getValue());
                return m;
            })
            .collect(java.util.stream.Collectors.toList());

        // Hourly series — ordered 0..23
        List<Map<String, Object>> hourlySeries = new ArrayList<>();
        for (int h = 0; h < 24; h++) {
            Map<String, Object> m = new HashMap<>();
            m.put("hour", h);
            m.put("count", hourlyBuckets.getOrDefault(h, 0));
            hourlySeries.add(m);
        }

        // Recent events: last 50 (already sorted DESC by repo)
        List<Map<String, Object>> recentEvents = all.stream()
            .limit(50)
            .map(row -> {
                Map<String, Object> ev = new HashMap<>();
                ev.put("raw", row.getDescription() != null ? row.getDescription()
                    : (row.getAttackType() != null ? row.getAttackType() : ""));
                ev.put("sourceIp", row.getSourceIp());
                ev.put("protocol", row.getProtocol());
                ev.put("severity", row.getSeverity() != null ? row.getSeverity().toUpperCase() : "LOW");
                return ev;
            })
            .collect(java.util.stream.Collectors.toList());

        stats.put("totalConnections", totalConnections);
        stats.put("modbusRequests", protocolCounts.getOrDefault("MODBUS", 0));
        stats.put("uniqueIPs", ips.size());
        stats.put("uniqueSessions", sessions.size());
        stats.put("resetConnections", resetCount);
        stats.put("errorCount", errorCount);
        stats.put("totalLogs", totalConnections); // same as totalConnections in DB-backed mode
        stats.put("isRunning", isRunning);

        // Breakdown maps
        stats.put("protocolBreakdown", protocolCounts);
        stats.put("severityBreakdown", severityCounts);
        stats.put("modbusFunctionBreakdown", modbusFunctionCounts);
        stats.put("httpMethodBreakdown", httpMethodCounts);
        stats.put("httpPathBreakdown", httpPathCounts);

        // Ordered series
        stats.put("topAttackers", topAttackers);
        stats.put("hourlySeries", hourlySeries);
        stats.put("recentEvents", recentEvents);

        return stats;
    }
    
    @PreDestroy
    public void cleanup() {
        logger.info("Cleaning up ConpotService");
        stopConpot();
    }
} 