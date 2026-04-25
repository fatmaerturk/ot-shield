package com.safetech.otshield.controller;

import com.safetech.otshield.dto.research.ResearchDocumentDTO;
import com.safetech.otshield.model.research.ResearchDocument;
import com.safetech.otshield.repository.research.ResearchDocumentRepository;
import com.safetech.otshield.service.research.ResearchIngestService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

/**
 * REST surface for the Research Studio Library. Deliberately small:
 * upload, list, delete. The heavy lifting (extract / chunk / embed)
 * happens asynchronously inside {@link ResearchIngestService}, so the
 * upload endpoint returns almost immediately and the client polls the
 * list endpoint to watch a document progress from {@code UPLOADED}
 * through {@code PROCESSING} to {@code READY}.
 *
 * <p>There is no authentication model on these endpoints beyond the
 * global SecurityConfig permit-all for {@code /api/research/**} - the
 * whole product runs on a private network and the HMGCC air-gapped
 * deployment target doesn't introduce an identity layer here. When the
 * shipped platform adds multi-tenancy we'll route through the same
 * {@code X-OT-Tenant-Id} filter the rest of the API uses.
 */
@RestController
@RequestMapping("/api/research/documents")
@RequiredArgsConstructor
@Slf4j
public class ResearchController {

    private final ResearchIngestService ingestService;
    private final ResearchDocumentRepository documentRepository;

    /**
     * Library listing, newest first. Polled by the UI every few seconds
     * while any document is still {@code PROCESSING}. Honours
     * {@code X-Bundle-Id} so the Library table only shows the active
     * bundle's uploads; absent header returns everything (legacy).
     */
    @GetMapping
    public ResponseEntity<List<ResearchDocumentDTO>> list(
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId) {
        List<ResearchDocumentDTO> rows = (bundleId == null || bundleId.isBlank())
                ? documentRepository.findAllByOrderByUploadedAtDesc()
                        .stream().map(ResearchDocumentDTO::from).toList()
                : documentRepository.findByBundleIdOrderByUploadedAtDesc(bundleId)
                        .stream().map(ResearchDocumentDTO::from).toList();
        return ResponseEntity.ok(rows);
    }

    /**
     * Upload a reference document (PDF, markdown, txt, csv). The
     * response contains the freshly-created metadata row with status
     * {@code UPLOADED} - processing happens in the background.
     *
     * <p>The optional {@code productLabel} form field lets users tag a
     * document with the machine it describes (e.g. "Siemens S7-1500
     * manual") so the Library UI can group by product.
     */
    @PostMapping("/upload")
    public ResponseEntity<ResearchDocumentDTO> upload(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "productLabel", required = false) String productLabel,
            @RequestHeader(value = "X-Bundle-Id", required = false) String bundleId) {
        try {
            ResearchDocument doc = ingestService.ingest(file, productLabel,
                    (bundleId == null || bundleId.isBlank()) ? null : bundleId);
            return ResponseEntity.accepted().body(ResearchDocumentDTO.from(doc));
        } catch (IllegalArgumentException e) {
            log.warn("Bad upload: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        } catch (Exception e) {
            log.error("Upload failed: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().build();
        }
    }

    /** Hard-delete a document and every chunk/vector it produced. */
    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> delete(@PathVariable String id) {
        ingestService.delete(id);
        return ResponseEntity.ok(Map.of("deleted", true, "id", id));
    }

    /**
     * Re-queue processing for a document stuck on UPLOADED (or a FAILED
     * row you want to retry). The UI surfaces this as a "Retry" button
     * so operators don't have to re-upload a 40 MB PDF to recover.
     */
    @PostMapping("/{id}/reingest")
    public ResponseEntity<Map<String, Object>> reingest(@PathVariable String id) {
        boolean queued = ingestService.reingest(id);
        if (!queued) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.accepted().body(Map.of("reingested", true, "id", id));
    }

    /**
     * Rebuild the in-memory vector store from the persistent chunk
     * table. Useful when RAG starts returning phantom citations (e.g.
     * after a hot reload or an interrupted delete left stale entries
     * in RAM). The UI surfaces this as a "Rebuild knowledge base"
     * button on the Library tab.
     */
    @PostMapping("/reconcile")
    public ResponseEntity<Map<String, Object>> reconcile() {
        int kept = ingestService.reconcileVectorStore();
        return ResponseEntity.ok(Map.of(
                "reconciled", true,
                "chunksInStore", kept
        ));
    }

    /**
     * Reassign a document's source-type class. Accepts a JSON body
     * {@code {"sourceType": "VENDOR_MANUAL"}}. Invalid enum values are
     * rejected with 400 so we never persist a free-text string in the
     * source_type column. The existing chunks are NOT re-embedded -
     * source type is pure metadata on the parent row.
     */
    @PatchMapping("/{id}/source-type")
    public ResponseEntity<ResearchDocumentDTO> setSourceType(
            @PathVariable String id,
            @RequestBody Map<String, String> body) {
        String raw = body == null ? null : body.get("sourceType");
        if (raw == null || raw.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        ResearchDocument.SourceType parsed;
        try {
            parsed = ResearchDocument.SourceType.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException e) {
            log.warn("Rejecting unknown source type '{}' on document {}", raw, id);
            return ResponseEntity.badRequest().build();
        }
        return documentRepository.findById(id)
                .map(d -> {
                    d.setSourceType(parsed);
                    documentRepository.save(d);
                    return ResponseEntity.ok(ResearchDocumentDTO.from(d));
                })
                .orElse(ResponseEntity.notFound().build());
    }
}
