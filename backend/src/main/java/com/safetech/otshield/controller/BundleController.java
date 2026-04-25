package com.safetech.otshield.controller;

import com.safetech.otshield.dto.research.BundleDTO;
import com.safetech.otshield.dto.research.BundleRequestDTOs.CreateRequest;
import com.safetech.otshield.dto.research.BundleRequestDTOs.UpdateRequest;
import com.safetech.otshield.model.research.ResearchBundle;
import com.safetech.otshield.service.research.BundleService;
import com.safetech.otshield.service.research.BundleSnapshotService;
import com.safetech.otshield.service.research.BundleSnapshotService.Snapshot;
import com.safetech.otshield.service.research.ReportService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * REST surface for the bundle sidebar.
 *
 * <pre>
 * GET    /api/research/bundles           - list, sidebar-ready with roll-ups
 * GET    /api/research/bundles/{id}      - single bundle + roll-ups
 * POST   /api/research/bundles           - create
 * PATCH  /api/research/bundles/{id}      - partial edit
 * DELETE /api/research/bundles/{id}      - hard delete (child FKs go NULL)
 * </pre>
 *
 * <p>Falls under the existing permit-all for {@code /api/research/**}.
 */
@RestController
@RequestMapping("/api/research/bundles")
@RequiredArgsConstructor
@Slf4j
public class BundleController {

    private final BundleService bundleService;
    private final BundleSnapshotService snapshotService;
    private final ReportService reportService;

    @GetMapping
    public ResponseEntity<List<BundleDTO>> list() {
        List<ResearchBundle> bundles = bundleService.list();
        List<BundleDTO> rows = bundles.stream()
                .map(b -> BundleDTO.from(
                        b,
                        bundleService.countDocuments(b.getId()),
                        bundleService.countThreads(b.getId()),
                        bundleService.countFindings(b.getId()),
                        bundleService.countVulns(b.getId())))
                .toList();
        return ResponseEntity.ok(rows);
    }

    @GetMapping("/{id}")
    public ResponseEntity<BundleDTO> get(@PathVariable String id) {
        return bundleService.get(id)
                .map(b -> BundleDTO.from(
                        b,
                        bundleService.countDocuments(b.getId()),
                        bundleService.countThreads(b.getId()),
                        bundleService.countFindings(b.getId()),
                        bundleService.countVulns(b.getId())))
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PostMapping
    public ResponseEntity<BundleDTO> create(@RequestBody CreateRequest req) {
        try {
            ResearchBundle b = bundleService.create(req);
            return ResponseEntity.ok(BundleDTO.from(b, 0, 0, 0, 0));
        } catch (IllegalArgumentException e) {
            log.warn("Bad bundle create: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    @PatchMapping("/{id}")
    public ResponseEntity<BundleDTO> update(@PathVariable String id, @RequestBody UpdateRequest req) {
        return bundleService.update(id, req)
                .map(b -> BundleDTO.from(
                        b,
                        bundleService.countDocuments(b.getId()),
                        bundleService.countThreads(b.getId()),
                        bundleService.countFindings(b.getId()),
                        bundleService.countVulns(b.getId())))
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable String id) {
        bundleService.delete(id);
        return ResponseEntity.ok(Map.of("deleted", true, "id", id));
    }

    /**
     * Stream the bundle as a ZIP for air-gapped hand-off.
     *
     * <p>The content is built in memory (manifest + documents, no
     * embeddings) so a 50 MB bundle is fine. We set {@code
     * Content-Disposition: attachment} so the browser triggers a
     * download rather than rendering the bytes.
     */
    @GetMapping("/{id}/snapshot.zip")
    public ResponseEntity<byte[]> snapshot(@PathVariable String id) {
        return snapshotService.buildFor(id)
                .map((Snapshot snap) -> ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION,
                                "attachment; filename=\"" + snap.filename() + "\"")
                        .contentType(MediaType.valueOf("application/zip"))
                        .body(snap.data()))
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * Render a polished PDF report scoped to this bundle. Content:
     * cover, executive summary, findings ledger, vulnerability
     * observations, thread transcripts (with confidence + citation
     * + consistency roll-ups). Suitable for handing to a reviewer.
     */
    @GetMapping("/{id}/report.pdf")
    public ResponseEntity<byte[]> report(@PathVariable String id) {
        byte[] pdf = reportService.buildBundleReport(id);
        String safeId = id == null ? "bundle" : id.replaceAll("[^A-Za-z0-9_-]", "");
        String filename = "otshield-research-report-" + safeId + ".pdf";
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + filename + "\"")
                .contentType(MediaType.APPLICATION_PDF)
                .body(pdf);
    }
}
