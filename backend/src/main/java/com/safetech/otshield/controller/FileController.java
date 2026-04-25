package com.safetech.otshield.controller;

import com.safetech.otshield.model.PacketInfo;
import com.safetech.otshield.service.PcapAnalysisService;
import com.safetech.otshield.service.AssetService;
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
    private final String uploadDir;

    public FileController(PcapAnalysisService pcapAnalysisService, AssetService assetService) {
        this.pcapAnalysisService = pcapAnalysisService;
        this.assetService = assetService;
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
            @RequestParam(defaultValue = "500") int size) {
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

            // Analyze the PCAP file
            List<PacketInfo> allPackets = pcapAnalysisService.analyzePcapFile(filePath.toAbsolutePath().toString());
            int total = allPackets.size();
            
            // Detect and save new assets from packet analysis
            try {
                pcapAnalysisService.detectAndSaveAssets(allPackets);
            } catch (Exception e) {
                // Log error but don't fail the upload
                System.err.println("Error during asset detection: " + e.getMessage());
            }
            
            // Calculate slice for pagination
            int fromIndex = Math.min(page * size, total);
            int toIndex = Math.min(fromIndex + size, total);
            List<PacketInfo> pagePackets = allPackets.subList(fromIndex, toIndex);
            
            // Build result with total count and page data
            Map<String, Object> result = new HashMap<>();
            result.put("total", total);
            result.put("packets", pagePackets);
            
            // Add asset detection info
            Map<String, Object> assetInfo = new HashMap<>();
            assetInfo.put("assetsDetected", true);
            assetInfo.put("message", "New assets have been automatically detected and saved to the asset inventory.");
            result.put("assetDetection", assetInfo);
            
            return ResponseEntity.ok(result);
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
} 