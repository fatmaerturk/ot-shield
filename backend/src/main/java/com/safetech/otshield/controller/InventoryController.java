package com.safetech.otshield.controller;

import com.safetech.otshield.dto.research.InventoryItemDTO;
import com.safetech.otshield.dto.research.InventoryRequestDTOs.CreateRequest;
import com.safetech.otshield.dto.research.InventoryRequestDTOs.UpdateRequest;
import com.safetech.otshield.model.research.InventoryItem;
import com.safetech.otshield.model.research.InventoryItem.Kind;
import com.safetech.otshield.model.research.ExtractionJob;
import com.safetech.otshield.service.research.InventoryDeepExtractor;
import com.safetech.otshield.service.research.InventoryExtractor;
import com.safetech.otshield.service.research.InventoryExtractor.ExtractionResult;
import com.safetech.otshield.service.research.InventoryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * REST surface for the bundle inventory tab.
 *
 * <pre>
 * GET    /api/research/inventory               - list for active bundle
 *                                              - optional ?kinds=COMPONENT,PORT
 * GET    /api/research/inventory/{id}          - single item
 * POST   /api/research/inventory               - create
 * PATCH  /api/research/inventory/{id}          - edit
 * DELETE /api/research/inventory/{id}          - delete
 * </pre>
 *
 * <p>All endpoints require {@code X-Bundle-Id}. Missing header returns
 * 400 so the UI can surface a clear error instead of silently showing
 * cross-bundle results.
 */
@RestController
@RequestMapping("/api/research/inventory")
@RequiredArgsConstructor
@Slf4j
public class InventoryController {

    private final InventoryService inventoryService;
    private final InventoryExtractor inventoryExtractor;
    private final InventoryDeepExtractor inventoryDeepExtractor;

    @GetMapping
    public ResponseEntity<List<InventoryItemDTO>> list(
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId,
            @RequestParam(required = false) String kinds) {
        String b = blankToNull(bundleId);
        if (b == null) return ResponseEntity.badRequest().build();

        List<Kind> parsedKinds = parseKinds(kinds);
        List<InventoryItem> rows = parsedKinds.isEmpty()
                ? inventoryService.list(b)
                : inventoryService.listByKinds(b, parsedKinds);
        return ResponseEntity.ok(rows.stream().map(InventoryItemDTO::from).toList());
    }

    @GetMapping("/{id}")
    public ResponseEntity<InventoryItemDTO> get(@PathVariable String id) {
        return inventoryService.get(id)
                .map(InventoryItemDTO::from)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<InventoryItemDTO> create(
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId,
            @RequestBody CreateRequest req) {
        String b = blankToNull(bundleId);
        if (b == null) return ResponseEntity.badRequest().build();
        try {
            InventoryItem i = inventoryService.create(b, req);
            return ResponseEntity.ok(InventoryItemDTO.from(i));
        } catch (IllegalArgumentException e) {
            log.warn("Bad inventory create: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    @PatchMapping("/{id}")
    public ResponseEntity<InventoryItemDTO> update(
            @PathVariable String id,
            @RequestBody UpdateRequest req) {
        return inventoryService.update(id, req)
                .map(InventoryItemDTO::from)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable String id) {
        inventoryService.delete(id);
        return ResponseEntity.ok(Map.of("deleted", true, "id", id));
    }

    /**
     * Run the regex inventory extractor over every READY document in
     * the active bundle. Returns a summary of what was created.
     *
     * <p>Synchronous - the scan is fast (milliseconds per chunk) and
     * runs entirely in memory, so there is no need for the async
     * polling dance the Summary tab uses for Ollama.
     */
    @PostMapping("/extract")
    public ResponseEntity<ExtractionResult> extract(
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId) {
        String b = blankToNull(bundleId);
        if (b == null) return ResponseEntity.badRequest().build();
        try {
            ExtractionResult result = inventoryExtractor.extractForBundle(b);
            log.info("Inventory extract for bundle={} -> {}", b, result);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Inventory extract failed for bundle {}: {}", b, e.getMessage(), e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /**
     * Kick off async LLM-driven deep extraction. Returns 202 with the
     * job row in {@code GENERATING}; frontend polls {@link #deepStatus}.
     */
    @PostMapping("/extract/deep")
    public ResponseEntity<ExtractionJob> deepExtract(
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId) {
        String b = blankToNull(bundleId);
        if (b == null) return ResponseEntity.badRequest().build();
        try {
            ExtractionJob job = inventoryDeepExtractor.start(b);
            return ResponseEntity.accepted().body(job);
        } catch (Exception e) {
            log.error("Deep extract start failed for bundle {}: {}", b, e.getMessage(), e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /** Status for the in-flight deep extraction (null-safe idle default). */
    @GetMapping("/extract/deep/status")
    public ResponseEntity<ExtractionJob> deepStatus(
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId) {
        String b = blankToNull(bundleId);
        if (b == null) return ResponseEntity.badRequest().build();
        ExtractionJob job = inventoryDeepExtractor.status(b).orElseGet(() ->
                ExtractionJob.builder().bundleId(b).status("IDLE").build());
        return ResponseEntity.ok(job);
    }

    // ---- Helpers ------------------------------------------------------

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }

    /** Accept a comma-separated kinds list; ignore unknown values silently. */
    private static List<Kind> parseKinds(String raw) {
        List<Kind> out = new ArrayList<>();
        if (raw == null || raw.isBlank()) return out;
        for (String token : Arrays.asList(raw.split(","))) {
            String t = token == null ? "" : token.trim();
            if (t.isEmpty()) continue;
            try { out.add(Kind.valueOf(t)); } catch (IllegalArgumentException ignored) {}
        }
        return out;
    }
}
