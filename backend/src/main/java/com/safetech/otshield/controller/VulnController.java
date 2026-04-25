package com.safetech.otshield.controller;

import com.safetech.otshield.dto.research.VulnEventDTO;
import com.safetech.otshield.dto.research.VulnKpiDTO;
import com.safetech.otshield.dto.research.VulnObservationDTO;
import com.safetech.otshield.dto.research.VulnRequestDTOs.CreateRequest;
import com.safetech.otshield.dto.research.VulnRequestDTOs.PromoteRequest;
import com.safetech.otshield.dto.research.VulnRequestDTOs.TransitionRequest;
import com.safetech.otshield.dto.research.VulnRequestDTOs.UpdateRequest;
import com.safetech.otshield.model.research.VulnObservation;
import com.safetech.otshield.model.research.VulnObservation.ComponentType;
import com.safetech.otshield.model.research.VulnObservation.VulnSeverity;
import com.safetech.otshield.model.research.VulnObservation.VulnStatus;
import com.safetech.otshield.service.research.VulnService;
import com.safetech.otshield.service.research.VulnSignalScanner;
import com.safetech.otshield.service.research.VulnSignalScanner.SignalScanResult;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.EnumSet;
import java.util.List;
import java.util.Map;

/**
 * REST surface for the Vulnerability Observations workflow.
 *
 * <pre>
 * GET    /api/research/vulns                  - list (with filters)
 * GET    /api/research/vulns/kpi              - KPI counts for the tab header
 * GET    /api/research/vulns/{id}             - single observation
 * GET    /api/research/vulns/{id}/events      - audit timeline
 * GET    /api/research/vulns/{id}/transitions - legal next statuses
 * POST   /api/research/vulns                  - manual create
 * POST   /api/research/vulns/promote          - from an assistant message
 * PATCH  /api/research/vulns/{id}             - partial edit
 * POST   /api/research/vulns/{id}/transition  - status transition
 * DELETE /api/research/vulns/{id}             - hard delete (cascades events)
 * </pre>
 *
 * <p>Falls under the existing permit-all on {@code /api/research/**}
 * registered by {@code SecurityConfig}.
 */
@RestController
@RequestMapping("/api/research/vulns")
@RequiredArgsConstructor
@Slf4j
public class VulnController {

    private final VulnService vulnService;
    private final VulnSignalScanner signalScanner;

    @GetMapping
    public ResponseEntity<List<VulnObservationDTO>> list(
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String componentType,
            @RequestParam(required = false) Boolean needsMoreSources,
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId) {

        VulnStatus statusEnum         = parseOrNull(VulnStatus.class, status);
        VulnSeverity severityEnum     = parseOrNull(VulnSeverity.class, severity);
        ComponentType componentEnum   = parseOrNull(ComponentType.class, componentType);
        String bundle                 = blankToNull(bundleId);

        List<VulnObservation> rows = (statusEnum == null && severityEnum == null
                && componentEnum == null && needsMoreSources == null && bundle == null)
                ? vulnService.list()
                : vulnService.search(statusEnum, severityEnum, componentEnum, needsMoreSources, bundle);

        return ResponseEntity.ok(rows.stream().map(VulnObservationDTO::from).toList());
    }

    @GetMapping("/kpi")
    public ResponseEntity<VulnKpiDTO> kpi(
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId) {
        return ResponseEntity.ok(vulnService.kpi(blankToNull(bundleId)));
    }

    @GetMapping("/{id}")
    public ResponseEntity<VulnObservationDTO> get(@PathVariable String id) {
        return vulnService.get(id)
                .map(v -> ResponseEntity.ok(VulnObservationDTO.from(v)))
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{id}/events")
    public ResponseEntity<List<VulnEventDTO>> events(@PathVariable String id) {
        return ResponseEntity.ok(
                vulnService.events(id).stream().map(VulnEventDTO::from).toList());
    }

    /**
     * Return the list of next legal statuses for this observation's
     * current state. Lets the UI render only the enabled buttons and
     * keeps the state-machine single-sourced in the service.
     */
    @GetMapping("/{id}/transitions")
    public ResponseEntity<Map<String, Object>> transitions(@PathVariable String id) {
        return vulnService.get(id).map(v -> {
            EnumSet<VulnStatus> next = vulnService.allowedTransitions(v.getStatus());
            return ResponseEntity.ok(Map.<String, Object>of(
                    "from", v.getStatus().name(),
                    "next", next.stream().map(Enum::name).toList()
            ));
        }).orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<VulnObservationDTO> create(
            @RequestBody CreateRequest req,
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleHeader) {
        try {
            CreateRequest effective = applyBundleHeader(req, bundleHeader);
            VulnObservation v = vulnService.create(effective);
            return ResponseEntity.ok(VulnObservationDTO.from(v));
        } catch (IllegalArgumentException e) {
            log.warn("Bad vuln create: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    @PostMapping("/promote")
    public ResponseEntity<VulnObservationDTO> promote(
            @RequestBody PromoteRequest req,
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleHeader) {
        try {
            PromoteRequest effective = applyBundleHeader(req, bundleHeader);
            VulnObservation v = vulnService.promote(effective);
            return ResponseEntity.ok(VulnObservationDTO.from(v));
        } catch (IllegalArgumentException e) {
            log.warn("Bad vuln promote: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    /** Header falls through only when the body didn't already specify a bundle. */
    private CreateRequest applyBundleHeader(CreateRequest req, String header) {
        String h = blankToNull(header);
        if (h == null || req.bundleId() != null) return req;
        return new CreateRequest(
                req.title(), req.summary(), req.componentType(), req.componentRef(),
                req.affectedProduct(), req.severity(), req.cveId(), req.cvssV31(),
                req.confidence(), req.needsMoreSources(), req.alternativeHypotheses(),
                req.tags(), req.createdBy(), h);
    }

    private PromoteRequest applyBundleHeader(PromoteRequest req, String header) {
        String h = blankToNull(header);
        if (h == null || req.bundleId() != null) return req;
        return new PromoteRequest(
                req.threadId(), req.messageId(), req.title(), req.componentType(),
                req.componentRef(), req.affectedProduct(), req.severity(),
                req.confidence(), req.needsMoreSources(), req.alternativeHypotheses(),
                req.tags(), req.createdBy(), h);
    }

    @PatchMapping("/{id}")
    public ResponseEntity<VulnObservationDTO> update(
            @PathVariable String id,
            @RequestBody UpdateRequest req,
            @RequestParam(required = false, defaultValue = "") String actor) {
        return vulnService.update(id, req, actor)
                .map(v -> ResponseEntity.ok(VulnObservationDTO.from(v)))
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping("/{id}/transition")
    public ResponseEntity<VulnObservationDTO> transition(
            @PathVariable String id,
            @RequestBody TransitionRequest req) {
        try {
            return vulnService.transition(id, req)
                    .map(v -> ResponseEntity.ok(VulnObservationDTO.from(v)))
                    .orElse(ResponseEntity.notFound().build());
        } catch (IllegalArgumentException | IllegalStateException e) {
            log.warn("Bad transition: {}", e.getMessage());
            return ResponseEntity.badRequest()
                    .body(null);
        }
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable String id) {
        vulnService.delete(id);
        return ResponseEntity.ok(Map.of("deleted", true, "id", id));
    }

    /**
     * Run the regex signal scanner over every READY document in the
     * active bundle. Each unique match becomes a DRAFT
     * {@link com.safetech.otshield.model.research.VulnObservation}
     * with confidence LOW and needsMoreSources=true so the researcher
     * has to validate before anything is treated as real.
     *
     * <p>Synchronous - millisecond-latency pass over the DB, no LLM.
     */
    @PostMapping("/signals/scan")
    public ResponseEntity<SignalScanResult> scanSignals(
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId) {
        String b = blankToNull(bundleId);
        if (b == null) return ResponseEntity.badRequest().build();
        try {
            SignalScanResult result = signalScanner.scanForBundle(b);
            log.info("Vuln signal scan for bundle={} -> {}", b, result);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Vuln signal scan failed for bundle {}: {}", b, e.getMessage(), e);
            return ResponseEntity.internalServerError().build();
        }
    }

    // ---- Helpers -------------------------------------------------------

    private static <E extends Enum<E>> E parseOrNull(Class<E> type, String raw) {
        if (raw == null || raw.isBlank()) return null;
        try {
            return Enum.valueOf(type, raw);
        } catch (Exception e) {
            return null;
        }
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }
}
