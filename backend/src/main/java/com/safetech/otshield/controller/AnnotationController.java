package com.safetech.otshield.controller;

import com.safetech.otshield.dto.research.AnnotationDTO;
import com.safetech.otshield.model.research.ResearchAnnotation;
import com.safetech.otshield.model.research.ResearchAnnotation.Kind;
import com.safetech.otshield.model.research.ResearchAnnotation.TargetKind;
import com.safetech.otshield.service.research.AnnotationService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST surface for researcher annotations — sticky notes, highlights,
 * and flags that researchers attach to messages, documents, or
 * citations during a tear-down. Sits under {@code /api/research/**}
 * which is already permit-all, same as findings and threads.
 */
@RestController
@RequestMapping("/api/research/annotations")
@RequiredArgsConstructor
@Slf4j
public class AnnotationController {

    private final AnnotationService service;

    /**
     * List annotations. Accepts either:
     * <ul>
     *   <li>{@code ?targetKind=MESSAGE&targetId=abc} — just that target</li>
     *   <li>{@code ?bundleId=...} — everything in one bundle</li>
     * </ul>
     * If both are supplied targetKind / targetId wins.
     */
    @GetMapping
    public ResponseEntity<List<AnnotationDTO>> list(
            @RequestParam(required = false) String targetKind,
            @RequestParam(required = false) String targetId,
            @RequestParam(required = false) String bundleId) {
        List<ResearchAnnotation> rows;
        if (targetKind != null && !targetKind.isBlank() && targetId != null && !targetId.isBlank()) {
            TargetKind tk;
            try {
                tk = TargetKind.valueOf(targetKind.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().build();
            }
            rows = service.listForTarget(tk, targetId);
        } else if (bundleId != null && !bundleId.isBlank()) {
            rows = service.listForBundle(bundleId);
        } else {
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(rows.stream().map(AnnotationDTO::from).toList());
    }

    /**
     * Create a new annotation. Body:
     * <pre>
     * { "bundleId": "...",
     *   "targetKind": "MESSAGE|DOCUMENT|CITATION|FREEFORM",
     *   "targetId":   "...",
     *   "kind":       "NOTE|HIGHLIGHT|FLAG|VERIFIED",
     *   "body":       "...",
     *   "tags":       "comma,separated",
     *   "author":     "..." }
     * </pre>
     */
    @PostMapping
    public ResponseEntity<AnnotationDTO> create(@RequestBody Map<String, String> body) {
        if (body == null) return ResponseEntity.badRequest().build();
        String targetKindRaw = body.get("targetKind");
        String targetId = body.get("targetId");
        String text = body.get("body");
        if (targetKindRaw == null || targetId == null || text == null || text.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        TargetKind targetKind;
        try {
            targetKind = TargetKind.valueOf(targetKindRaw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest().build();
        }
        Kind kind = Kind.NOTE;
        String kindRaw = body.get("kind");
        if (kindRaw != null && !kindRaw.isBlank()) {
            try {
                kind = Kind.valueOf(kindRaw.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().build();
            }
        }
        ResearchAnnotation saved = service.create(
                body.get("bundleId"),
                targetKind,
                targetId,
                kind,
                text,
                body.get("tags"),
                body.get("author"));
        return ResponseEntity.ok(AnnotationDTO.from(saved));
    }

    /** Update body / kind / tags. Any field that's missing is left untouched. */
    @PatchMapping("/{id}")
    public ResponseEntity<AnnotationDTO> update(@PathVariable String id,
                                                @RequestBody Map<String, String> body) {
        if (body == null) return ResponseEntity.badRequest().build();
        Kind kind = null;
        String kindRaw = body.get("kind");
        if (kindRaw != null && !kindRaw.isBlank()) {
            try {
                kind = Kind.valueOf(kindRaw.trim().toUpperCase());
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest().build();
            }
        }
        return service.update(id, kind, body.get("body"), body.get("tags"))
                .map(AnnotationDTO::from)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable String id) {
        boolean deleted = service.delete(id);
        if (!deleted) return ResponseEntity.notFound().build();
        return ResponseEntity.ok(Map.of("deleted", true, "id", id));
    }
}
