package com.safetech.otshield.controller;

import com.safetech.otshield.dto.cases.*;
import com.safetech.otshield.model.CasePriority;
import com.safetech.otshield.model.CaseStatus;
import com.safetech.otshield.service.CaseService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/cases")
@RequiredArgsConstructor
@Slf4j
@CrossOrigin(origins = "*")
public class CaseController {

    private final CaseService caseService;

    // ---------- list / detail / stats ----------

    @GetMapping
    public ResponseEntity<Page<CaseDTO>> list(
            @RequestParam(required = false) CaseStatus status,
            @RequestParam(required = false) CasePriority priority,
            @RequestParam(required = false) String assigneeId,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size,
            @RequestParam(defaultValue = "createdAt") String sortBy,
            @RequestParam(defaultValue = "desc") String sortDir
    ) {
        return ResponseEntity.ok(
                caseService.list(status, priority, assigneeId, search, page, size, sortBy, sortDir)
        );
    }

    @GetMapping("/{id}")
    public ResponseEntity<CaseDTO> get(@PathVariable String id) {
        return caseService.get(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/stats")
    public ResponseEntity<CaseStatsDTO> stats() {
        return ResponseEntity.ok(caseService.stats());
    }

    // ---------- create / update / transition ----------

    @PostMapping
    public ResponseEntity<CaseDTO> create(@RequestBody CreateCaseRequest req) {
        CaseDTO created = caseService.create(req);
        log.info("Case created: {}", created.getCaseNumber());
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @PatchMapping("/{id}")
    public ResponseEntity<CaseDTO> update(
            @PathVariable String id,
            @RequestBody UpdateCaseRequest req,
            @RequestHeader(value = "X-Actor-Name", required = false, defaultValue = "analyst") String actor
    ) {
        return caseService.update(id, req, actor)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/{id}/transition")
    public ResponseEntity<CaseDTO> transition(
            @PathVariable String id,
            @RequestBody CaseTransitionRequest req
    ) {
        return caseService.transition(id, req)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/{id}/assign")
    public ResponseEntity<CaseDTO> assign(
            @PathVariable String id,
            @RequestBody CaseAssignRequest req
    ) {
        return caseService.assign(id, req)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        return caseService.delete(id) ? ResponseEntity.noContent().build() : ResponseEntity.notFound().build();
    }

    // ---------- comments ----------

    @PostMapping("/{id}/comments")
    public ResponseEntity<CaseDTO> addComment(
            @PathVariable String id,
            @RequestBody CaseCommentRequest req
    ) {
        return caseService.addComment(id, req)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    // ---------- artifacts ----------

    @PostMapping("/{id}/artifacts")
    public ResponseEntity<CaseArtifactDTO> addArtifact(
            @PathVariable String id,
            @RequestBody CaseArtifactRequest req
    ) {
        return caseService.addArtifact(id, req)
                .map(a -> ResponseEntity.status(HttpStatus.CREATED).body(a))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}/artifacts/{artifactId}")
    public ResponseEntity<Void> removeArtifact(
            @PathVariable String id,
            @PathVariable String artifactId,
            @RequestHeader(value = "X-Actor-Name", required = false, defaultValue = "analyst") String actor
    ) {
        return caseService.removeArtifact(id, artifactId, actor)
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }

    // ---------- alert linking ----------

    @PostMapping("/{id}/alerts/{alertId}")
    public ResponseEntity<CaseDTO> linkAlert(
            @PathVariable String id,
            @PathVariable String alertId,
            @RequestHeader(value = "X-Actor-Name", required = false, defaultValue = "analyst") String actor
    ) {
        return caseService.linkAlert(id, alertId, actor)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}/alerts/{alertId}")
    public ResponseEntity<CaseDTO> unlinkAlert(
            @PathVariable String id,
            @PathVariable String alertId,
            @RequestHeader(value = "X-Actor-Name", required = false, defaultValue = "analyst") String actor
    ) {
        return caseService.unlinkAlert(id, alertId, actor)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
