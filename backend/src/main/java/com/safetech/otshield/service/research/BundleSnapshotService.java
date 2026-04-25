package com.safetech.otshield.service.research;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.safetech.otshield.model.research.*;
import com.safetech.otshield.repository.research.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Turns an entire research bundle into a single portable ZIP so a
 * researcher can hand an investigation off between machines, archive
 * it, or share it with a reviewer on an air-gapped network.
 *
 * <p>Zip layout:
 *
 * <pre>
 *   manifest.json           - full bundle state (metadata + all rows)
 *   summary.md              - markdown summary (if present)
 *   documents/{filename}    - original uploaded binaries
 *   README.txt              - short handover note
 * </pre>
 *
 * <p>We deliberately exclude the chunk embeddings: they are rebuilt
 * on re-ingest on the destination machine, and their binary format
 * is internal. The original documents are the source of truth.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BundleSnapshotService {

    private final ResearchBundleRepository bundleRepo;
    private final ResearchDocumentRepository documentRepo;
    private final ResearchThreadRepository threadRepo;
    private final ResearchMessageRepository messageRepo;
    private final ResearchFindingRepository findingRepo;
    private final VulnObservationRepository vulnRepo;
    private final VulnEventRepository vulnEventRepo;
    private final InventoryItemRepository inventoryRepo;
    private final BundleSummaryRepository summaryRepo;

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .enable(SerializationFeature.INDENT_OUTPUT);

    /** Shape of the result so the controller can set a sensible filename. */
    public record Snapshot(byte[] data, String filename) {}

    public Optional<Snapshot> buildFor(String bundleId) {
        ResearchBundle bundle = bundleRepo.findById(bundleId).orElse(null);
        if (bundle == null) return Optional.empty();

        // Gather everything upfront so the ZIP write is straight
        // streaming - less memory contention than interleaving DB
        // reads with stream writes.
        List<ResearchDocument> docs = documentRepo.findByBundleIdOrderByUploadedAtDesc(bundleId);
        List<ResearchThread> threads = threadRepo.findByBundleIdOrderByUpdatedAtDesc(bundleId);
        Map<String, List<ResearchMessage>> messagesByThread = new LinkedHashMap<>();
        for (ResearchThread t : threads) {
            messagesByThread.put(t.getId(), messageRepo.findByThreadIdOrderByCreatedAtAsc(t.getId()));
        }
        List<ResearchFinding> findings = findingRepo.findByBundleIdOrderByCreatedAtDesc(bundleId);
        List<VulnObservation> vulns = vulnRepo.findByBundleIdOrderByUpdatedAtDesc(bundleId);
        Map<String, List<VulnEvent>> eventsByVuln = new LinkedHashMap<>();
        for (VulnObservation v : vulns) {
            eventsByVuln.put(v.getId(), vulnEventRepo.findByVulnIdOrderByCreatedAtAsc(v.getId()));
        }
        List<InventoryItem> inventory = inventoryRepo.findByBundleIdOrderByUpdatedAtDesc(bundleId);
        BundleSummary summary = summaryRepo.findById(bundleId).orElse(null);

        Map<String, Object> manifest = new LinkedHashMap<>();
        manifest.put("schemaVersion", 1);
        manifest.put("exportedAt", LocalDateTime.now().toString());
        manifest.put("bundle", bundle);
        manifest.put("documents", docs);
        manifest.put("threads", threads);
        manifest.put("messagesByThread", messagesByThread);
        manifest.put("findings", findings);
        manifest.put("vulns", vulns);
        manifest.put("vulnEventsByVuln", eventsByVuln);
        manifest.put("inventory", inventory);
        manifest.put("summary", summary);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(baos)) {

            // README
            putEntry(zip, "README.txt",
                    ("OTShield Research bundle snapshot\n"
                            + "==================================\n\n"
                            + "Bundle: " + bundle.getName() + " (" + bundle.getSlug() + ")\n"
                            + "Exported: " + LocalDateTime.now() + "\n\n"
                            + "manifest.json carries the complete state of this bundle at\n"
                            + "export time: metadata, documents, threads and their full\n"
                            + "transcripts, findings, vulnerability observations with their\n"
                            + "audit events, inventory, and the latest summary.\n\n"
                            + "documents/ holds the original uploaded binaries. Re-ingest\n"
                            + "them on the destination machine to rebuild the vector store.\n"
                    ).getBytes());

            // manifest.json
            putEntry(zip, "manifest.json",
                    MAPPER.writerWithDefaultPrettyPrinter().writeValueAsBytes(manifest));

            // summary.md for convenience
            if (summary != null && summary.getText() != null && !summary.getText().isBlank()) {
                putEntry(zip, "summary.md", summary.getText().getBytes());
            }

            // Original documents
            for (ResearchDocument doc : docs) {
                String storagePath = doc.getStoragePath();
                if (storagePath == null || storagePath.isBlank()) continue;
                Path p = Paths.get(storagePath);
                if (!Files.isRegularFile(p)) {
                    log.warn("Snapshot: bundle={} missing file for doc {}: {}",
                            bundleId, doc.getId(), storagePath);
                    continue;
                }
                byte[] bytes;
                try {
                    bytes = Files.readAllBytes(p);
                } catch (IOException ioe) {
                    log.warn("Snapshot: bundle={} could not read {}: {}",
                            bundleId, storagePath, ioe.getMessage());
                    continue;
                }
                // Strip any leading paths, keep just the file name.
                putEntry(zip, "documents/" + sanitiseNameForZip(doc.getFileName()), bytes);
            }

        } catch (IOException e) {
            log.error("Snapshot: zip write failed for bundle {}: {}", bundleId, e.getMessage(), e);
            return Optional.empty();
        }

        String filename = "otshield-bundle-" + bundle.getSlug() + "-"
                + LocalDateTime.now().toString().replace(":", "-").replaceAll("\\..+$", "")
                + ".zip";
        return Optional.of(new Snapshot(baos.toByteArray(), filename));
    }

    private static void putEntry(ZipOutputStream zip, String name, byte[] data) throws IOException {
        ZipEntry entry = new ZipEntry(name);
        zip.putNextEntry(entry);
        zip.write(data);
        zip.closeEntry();
    }

    private static String sanitiseNameForZip(String name) {
        if (name == null || name.isBlank()) return "unnamed.bin";
        // The upload layer already strips path separators; this is a
        // belt-and-braces pass so a malicious file name can't escape.
        String cleaned = name.replace('\\', '/');
        int slash = cleaned.lastIndexOf('/');
        if (slash >= 0) cleaned = cleaned.substring(slash + 1);
        return cleaned;
    }
}
