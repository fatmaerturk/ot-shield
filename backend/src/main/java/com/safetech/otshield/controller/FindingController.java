package com.safetech.otshield.controller;

import com.safetech.otshield.dto.research.ResearchFindingDTO;
import com.safetech.otshield.model.research.ResearchFinding;
import com.safetech.otshield.service.research.FindingService;
import com.safetech.otshield.service.research.ThreadService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST surface for the curated Findings ledger.
 *
 * <p>Typical usage: the "Threads" tab shows conversations in flight;
 * when the analyst is satisfied with an assistant answer they POST
 * {@code /promote} with the message id to snapshot it here. Findings
 * then appear in the "Findings" tab where they can be edited, tagged,
 * and re-cited later without re-running retrieval.
 */
@RestController
@RequestMapping("/api/research/findings")
@RequiredArgsConstructor
@Slf4j
public class FindingController {

    private final FindingService findingService;
    private final ThreadService threadService;

    /** All findings, newest first. Honours {@code X-Bundle-Id}. */
    @GetMapping
    public ResponseEntity<List<ResearchFindingDTO>> list(
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId) {
        String scoped = (bundleId == null || bundleId.isBlank()) ? null : bundleId;
        List<ResearchFindingDTO> rows = findingService.listFindings(scoped)
                .stream().map(f -> ResearchFindingDTO.from(f, threadService))
                .toList();
        return ResponseEntity.ok(rows);
    }

    @GetMapping("/{id}")
    public ResponseEntity<ResearchFindingDTO> get(@PathVariable String id) {
        return findingService.getFinding(id)
                .map(f -> ResearchFindingDTO.from(f, threadService))
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Promote an assistant message into a finding.
     *
     * <p>Body shape: {@code {"messageId": "...", "title": "optional", "tags": "optional"}}.
     */
    @PostMapping("/promote")
    public ResponseEntity<ResearchFindingDTO> promote(
            @RequestBody Map<String, String> body,
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleHeader) {
        if (body == null || body.get("messageId") == null) {
            return ResponseEntity.badRequest().build();
        }
        try {
            String bundleId = resolveBundleId(body, bundleHeader);
            ResearchFinding finding = findingService.promoteMessage(
                    body.get("messageId"),
                    body.get("title"),
                    body.get("tags"),
                    bundleId);
            return ResponseEntity.ok(ResearchFindingDTO.from(finding, threadService));
        } catch (IllegalArgumentException e) {
            log.warn("Promote failed: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    /**
     * Analyst-authored finding that didn't come from a chat turn.
     * Body: {@code {"title": "...", "text": "...", "tags": "...", "bundleId": "..."}}.
     */
    @PostMapping
    public ResponseEntity<ResearchFindingDTO> create(
            @RequestBody Map<String, String> body,
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleHeader) {
        if (body == null || body.get("text") == null) {
            return ResponseEntity.badRequest().build();
        }
        String bundleId = resolveBundleId(body, bundleHeader);
        ResearchFinding finding = findingService.createFinding(
                body.get("title"), body.get("text"), body.get("tags"), bundleId);
        return ResponseEntity.ok(ResearchFindingDTO.from(finding, threadService));
    }

    private static String resolveBundleId(Map<String, String> body, String header) {
        String b = body == null ? null : body.get("bundleId");
        if (b != null && !b.isBlank()) return b;
        return (header == null || header.isBlank()) ? null : header;
    }

    /** Update title/text/tags. Missing fields are left untouched. */
    @PatchMapping("/{id}")
    public ResponseEntity<ResearchFindingDTO> update(
            @PathVariable String id,
            @RequestBody Map<String, String> body) {
        String title = body == null ? null : body.get("title");
        String text = body == null ? null : body.get("text");
        String tags = body == null ? null : body.get("tags");
        return findingService.updateFinding(id, title, text, tags)
                .map(f -> ResearchFindingDTO.from(f, threadService))
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable String id) {
        findingService.deleteFinding(id);
        return ResponseEntity.ok(Map.of("deleted", true, "id", id));
    }
}
