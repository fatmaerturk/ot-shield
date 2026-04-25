package com.safetech.otshield.controller;

import com.safetech.otshield.dto.threatintel.*;
import com.safetech.otshield.service.threatintel.ThreatIntelService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/threat-intel")
@CrossOrigin(origins = {"http://localhost:3000", "http://127.0.0.1:3000"})
public class ThreatIntelController {

    private final ThreatIntelService service;

    public ThreatIntelController(ThreatIntelService service) {
        this.service = service;
    }

    @GetMapping("/attackers")
    public ResponseEntity<List<AttackerIntelSummaryDTO>> list(
            @RequestParam(required = false) String country,
            @RequestParam(required = false) String asn,
            @RequestParam(required = false) Integer minScore) {
        return ResponseEntity.ok(service.listAttackers(country, asn, minScore));
    }

    @GetMapping("/attackers/{ip}")
    public ResponseEntity<AttackerIntelDetailDTO> detail(@PathVariable String ip) {
        AttackerIntelDetailDTO d = service.getAttackerDetail(ip);
        return d == null ? ResponseEntity.notFound().build() : ResponseEntity.ok(d);
    }

    @GetMapping("/ttp-matrix")
    public ResponseEntity<TtpMatrixDTO> matrix() {
        return ResponseEntity.ok(service.getEmptyMatrix());
    }

    @GetMapping("/campaigns")
    public ResponseEntity<List<CampaignClusterDTO>> campaigns() {
        return ResponseEntity.ok(service.listCampaigns());
    }

    @PostMapping("/export")
    public ResponseEntity<IocExportResultDTO> export(@RequestBody IocExportRequest req) {
        return ResponseEntity.ok(service.export(req));
    }

    @PostMapping("/push")
    public ResponseEntity<IntelPushResultDTO> push(@RequestBody IntelPushRequest req) {
        return ResponseEntity.ok(service.push(req));
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        return ResponseEntity.ok(Map.of("status", "UP", "component", "threat-intel"));
    }
}
