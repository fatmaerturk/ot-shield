package com.safetech.otshield.controller;

import com.safetech.otshield.dto.research.BundleSummaryDTO;
import com.safetech.otshield.model.research.BundleSummary;
import com.safetech.otshield.service.research.SummaryService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * REST surface for the Summary tab.
 *
 * <pre>
 * GET    /api/research/summary                     - current bundle's summary (may be empty)
 * POST   /api/research/summary/regenerate          - kick off LLM generation (blocking)
 * PATCH  /api/research/summary                     - overwrite with analyst-edited text
 * </pre>
 *
 * <p>All endpoints require an {@code X-Bundle-Id} header; the axios
 * interceptor injects it from the active bundle in the frontend. A
 * missing header returns 400 so the UI can surface a useful error.
 */
@RestController
@RequestMapping("/api/research/summary")
@RequiredArgsConstructor
@Slf4j
public class SummaryController {

    private final SummaryService summaryService;

    @GetMapping
    public ResponseEntity<BundleSummaryDTO> get(
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId) {
        String b = blankToNull(bundleId);
        if (b == null) return ResponseEntity.badRequest().build();
        // Null-safe: if no row yet, return an empty DTO so the frontend
        // can render the "No summary yet, hit Regenerate" empty state
        // without special-casing 404.
        BundleSummary s = summaryService.get(b).orElseGet(() ->
                BundleSummary.builder().bundleId(b).build());
        return ResponseEntity.ok(BundleSummaryDTO.from(s));
    }

    /**
     * Kick off async generation. Returns 202 immediately with the row
     * in {@code GENERATING} status; the frontend polls {@link #get} to
     * observe the eventual {@code READY} or {@code FAILED}.
     */
    @PostMapping("/regenerate")
    public ResponseEntity<BundleSummaryDTO> regenerate(
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId) {
        String b = blankToNull(bundleId);
        if (b == null) return ResponseEntity.badRequest().build();
        try {
            BundleSummary s = summaryService.regenerate(b);
            return ResponseEntity.accepted().body(BundleSummaryDTO.from(s));
        } catch (Exception e) {
            log.error("Summary regenerate failed for bundle {}: {}", b, e.getMessage(), e);
            return ResponseEntity.internalServerError().build();
        }
    }

    @PatchMapping
    public ResponseEntity<BundleSummaryDTO> edit(
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId,
            @RequestBody Map<String, String> body) {
        String b = blankToNull(bundleId);
        if (b == null) return ResponseEntity.badRequest().build();
        String text = body == null ? "" : body.getOrDefault("text", "");
        String editedBy = body == null ? null : body.get("editedBy");
        BundleSummary s = summaryService.saveEdit(b, text, editedBy);
        return ResponseEntity.ok(BundleSummaryDTO.from(s));
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s;
    }
}
