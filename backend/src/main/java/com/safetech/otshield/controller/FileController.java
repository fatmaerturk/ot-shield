package com.safetech.otshield.controller;

import com.safetech.otshield.model.PacketInfo;
import com.safetech.otshield.service.PcapAnalysisService;
import com.safetech.otshield.service.PcapJobService;
import com.safetech.otshield.service.AssetService;
import com.safetech.otshield.service.IngestionMonitorService;
import com.safetech.otshield.repository.AssetRepository;
import com.safetech.otshield.repository.AnomalyRepository;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Objects;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import java.util.Map;
import java.util.HashMap;

@RestController
@RequestMapping("/api")
public class FileController {

    private static final Logger logger = LoggerFactory.getLogger(FileController.class);
    private final PcapAnalysisService pcapAnalysisService;
    private final AssetService assetService;
    private final IngestionMonitorService ingestionMonitor;
    private final AssetRepository assetRepository;
    private final AnomalyRepository anomalyRepository;
    private final PcapJobService pcapJobService;
    private final String uploadDir;

    public FileController(PcapAnalysisService pcapAnalysisService, AssetService assetService,
                          IngestionMonitorService ingestionMonitor,
                          AssetRepository assetRepository, AnomalyRepository anomalyRepository,
                          PcapJobService pcapJobService) {
        this.pcapAnalysisService = pcapAnalysisService;
        this.assetService = assetService;
        this.ingestionMonitor = ingestionMonitor;
        this.assetRepository = assetRepository;
        this.anomalyRepository = anomalyRepository;
        this.pcapJobService = pcapJobService;
        // Use absolute path for uploads directory
        this.uploadDir = System.getProperty("user.dir") + "/uploads";
        
        // Ensure upload directory exists
        try {
            Path uploadPath = Paths.get(uploadDir);
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
                System.out.println("Created upload directory: " + uploadDir);
            }
        } catch (IOException e) {
            System.err.println("Error creating upload directory: " + e.getMessage());
        }
    }

    @GetMapping("/health/pcap")
    public ResponseEntity<Map<String, Object>> checkPcapHealth() {
        Map<String, Object> result = new HashMap<>();
        try {
            // Test if PCAP4J is working
            org.pcap4j.core.PcapNetworkInterface nif = org.pcap4j.core.Pcaps.getDevByName("lo0");
            result.put("status", "PCAP4J is working");
            result.put("available", nif != null);
            result.put("nativeLibrary", "available");
        } catch (UnsatisfiedLinkError e) {
            result.put("status", "PCAP4J available with fallback mode");
            result.put("available", true);
            result.put("nativeLibrary", "missing");
            result.put("message", "Native library not found, will use simulated data");
        } catch (Exception e) {
            result.put("status", "PCAP4J error");
            result.put("available", false);
            result.put("error", e.getMessage());
        }
        return ResponseEntity.ok(result);
    }

    @PostMapping("/upload/pcap")
    public ResponseEntity<Map<String, Object>> uploadPcapFile(
            @RequestParam("pcap") MultipartFile file,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "500") int size,
            @RequestHeader(value = "X-Sensor-Id", required = false) String sensorId,
            @RequestHeader(value = "X-Sensor-Host", required = false) String sensorHost,
            @RequestHeader(value = "X-Sensor-Iface", required = false) String sensorIface,
            HttpServletRequest request) {
        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body(Map.of("error", "Dosya boş olamaz"));
            }

            String filename = file.getOriginalFilename();
            if (filename == null || (!filename.toLowerCase().endsWith(".pcap") && !filename.toLowerCase().endsWith(".pcapng"))) {
                return ResponseEntity.badRequest().body(Map.of("error", "Sadece .pcap ve .pcapng dosyaları yüklenebilir"));
            }

            // Create upload directory if it doesn't exist
            Path uploadPath = Paths.get(uploadDir);
            if (!Files.exists(uploadPath)) {
                Files.createDirectories(uploadPath);
            }

            // Generate unique filename
            String uniqueFilename = UUID.randomUUID().toString() + "_" + file.getOriginalFilename();
            Path filePath = uploadPath.resolve(uniqueFilename);
            
            // Save the file
            Files.copy(file.getInputStream(), filePath);

            // Parsing a large capture is minutes of work (windowed streaming keeps
            // memory bounded, but ~573k DPI events from an ~87 MB IEC-104 file still
            // take ~8 min). Holding the HTTP request open that long just triggers
            // client timeouts that look like "server down", so hand the parse to a
            // background worker and return a jobId immediately; the UI polls
            // /api/upload/pcap/status/{jobId} for progress. Every DPI event, asset
            // and anomaly is persisted to the DB as each window completes, so the
            // real result is durable regardless of this in-memory job state.
            //
            // Capture every request-scoped value NOW: the MultipartFile and
            // HttpServletRequest (and values derived from them) are recycled the
            // moment this method returns, so the worker must not touch them.
            final String absPath = filePath.toAbsolutePath().toString();
            final String originalFilename = file.getOriginalFilename();
            final long fileSize = file.getSize();
            final String remoteAddr = request.getRemoteAddr();
            final String sId = sensorId, sHost = sensorHost, sIface = sensorIface;

            PcapJobService.Job job = pcapJobService.create(originalFilename);

            pcapJobService.submit(() -> {
                // Snapshot counts so we report what THIS capture actually produced.
                long assetsBefore = assetRepository.count();
                long anomaliesBefore = anomalyRepository.count();
                try {
                    PcapAnalysisService.PcapAnalysisResult analysis =
                            pcapAnalysisService.analyzePcapFile(absPath,
                                    (sessionId, processed, done) -> {
                                        job.pcapSessionId = sessionId;
                                        job.packetsProcessed = processed;
                                    });

                    long total = analysis.getTotal();
                    int newAssets = (int) Math.max(0, assetRepository.count() - assetsBefore);
                    int newAnomalies = (int) Math.max(0, anomalyRepository.count() - anomaliesBefore);

                    // Record this upload + its real deltas (never fabricated).
                    try {
                        List<String> protocols = analysis.getProtocols().stream()
                                .limit(16).collect(Collectors.toList());
                        int totalForMonitor = (int) Math.min(total, Integer.MAX_VALUE);
                        ingestionMonitor.track(sId, sHost, sIface, remoteAddr, originalFilename,
                                fileSize, totalForMonitor, total > 0, newAssets, newAnomalies, protocols);
                    } catch (Exception ignore) { /* monitoring must never break ingest */ }

                    job.total = total;
                    job.newAssets = newAssets;
                    job.newAnomalies = newAnomalies;
                    job.pcapSessionId = analysis.getPcapSessionId();
                    job.finishedAt = System.currentTimeMillis();
                    job.state = PcapJobService.State.DONE;
                    logger.info("PCAP job {} DONE: {} packets, {} new assets from {}",
                            job.jobId, total, newAssets, originalFilename);
                } catch (Exception e) {
                    logger.error("PCAP job {} failed for {}: {}", job.jobId, originalFilename, e.getMessage(), e);
                    job.error = (e.getMessage() != null) ? e.getMessage() : e.getClass().getSimpleName();
                    job.finishedAt = System.currentTimeMillis();
                    job.state = PcapJobService.State.ERROR;
                } finally {
                    // Analysis is persisted to the DB; the raw pcap on disk is no
                    // longer needed. Delete it - otherwise a SPAN sensor uploading
                    // one rolling capture per rotation window fills the disk over
                    // time (exactly what happened once: ~2500 files accumulated).
                    try { Files.deleteIfExists(Paths.get(absPath)); } catch (Exception ignore) { }
                }
            });

            Map<String, Object> accepted = new HashMap<>();
            accepted.put("status", "processing");
            accepted.put("jobId", job.jobId);
            accepted.put("filename", originalFilename);
            accepted.put("message", "Upload received - parsing in the background. "
                    + "Track progress at /api/upload/pcap/status/" + job.jobId + ".");
            return ResponseEntity.accepted().body(accepted);
        } catch (IOException e) {
            logger.error("File upload error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Dosya yükleme hatası: " + e.getMessage()));
        } catch (RuntimeException e) {
            logger.error("PCAP analysis error: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "PCAP analiz hatası: " + e.getMessage()));
        } catch (Exception e) {
            logger.error("Unexpected error during PCAP upload: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Beklenmeyen hata: " + e.getMessage()));
        }
    }

    /**
     * Live progress for a background PCAP parse started by {@code POST /upload/pcap}.
     * The UI polls this until {@code state} is {@code DONE} or {@code ERROR}.
     * Returns 404 once a job has been evicted (progress is in-memory only; the
     * parsed data itself lives in the DB).
     */
    @GetMapping("/upload/pcap/status/{jobId}")
    public ResponseEntity<Map<String, Object>> pcapJobStatus(@PathVariable String jobId) {
        PcapJobService.Job job = pcapJobService.get(jobId);
        if (job == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "Bilinmeyen veya süresi geçmiş iş: " + jobId));
        }
        Map<String, Object> s = new HashMap<>();
        s.put("jobId", job.jobId);
        s.put("filename", job.filename);
        s.put("state", job.state.name());            // PROCESSING | DONE | ERROR
        s.put("packetsProcessed", job.packetsProcessed);
        s.put("total", job.total);
        s.put("pcapSessionId", job.pcapSessionId);
        s.put("newAssets", job.newAssets);
        s.put("newAnomalies", job.newAnomalies);
        s.put("startedAt", job.startedAt);
        s.put("finishedAt", job.finishedAt);
        if (job.error != null) s.put("error", job.error);
        return ResponseEntity.ok(s);
    }
}
