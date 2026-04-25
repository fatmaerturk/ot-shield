package com.safetech.otshield.service.research;

import com.safetech.otshield.model.research.ResearchDocument;
import com.safetech.otshield.model.research.ResearchDocument.IngestStatus;
import com.safetech.otshield.model.research.ResearchDocumentChunk;
import com.safetech.otshield.repository.research.ResearchDocumentChunkRepository;
import com.safetech.otshield.repository.research.ResearchDocumentRepository;
import com.safetech.otshield.service.assistant.Chunk;
import com.safetech.otshield.service.assistant.EmbeddingService;
import com.safetech.otshield.service.assistant.VectorStore;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Front door of the Research Studio pipeline. Handles the whole life-cycle
 * of a reference document:
 *
 * <ol>
 *   <li>{@link #ingest} - receive a multipart upload, persist the file to
 *   disk, insert a metadata row with {@code UPLOADED} status, and kick
 *   off async processing so the HTTP caller returns immediately.</li>
 *   <li>processing - extract text (PDF for now; plain-text fallback for
 *   everything else), slice into overlapping chunks, embed each chunk,
 *   and write both the JPA rows and the in-memory vector entries.</li>
 *   <li>{@link #rehydrate} - on Spring startup, read every persisted
 *   chunk back out of Postgres and repopulate the {@link VectorStore}
 *   so search works without re-running the embedder.</li>
 *   <li>{@link #delete} - drop the row, the chunks, the on-disk file,
 *   and the vector-store entries so a deletion is permanent.</li>
 * </ol>
 *
 * <p>Ingest work runs on a single-thread executor: we'd rather be slow
 * and deterministic than flood Ollama with concurrent embed requests
 * that each timeout. The local model is CPU-bound and handles one
 * batch well - parallelising it does not speed things up.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ResearchIngestService {

    private final ResearchDocumentRepository documentRepository;
    private final ResearchDocumentChunkRepository chunkRepository;
    private final PdfExtractor pdfExtractor;
    private final Chunker chunker;
    private final EmbeddingService embeddings;
    private final VectorStore vectorStore;
    private final SourceTypeClassifier sourceTypeClassifier;

    /** Where we park the original uploaded binaries. */
    @Value("${otshield.research.storage-dir:data/research}")
    private String storageDir;

    /** Executor for async ingest pipeline work. */
    private final ExecutorService ingestExecutor = Executors.newSingleThreadExecutor(r -> {
        Thread t = new Thread(r, "research-ingest");
        t.setDaemon(true);
        return t;
    });

    /**
     * On startup, replay every persisted chunk back into the vector
     * store so RAG retrieval works against the full corpus without
     * waiting for someone to re-upload or re-embed anything. Also
     * calls {@link #reconcileVectorStore()} so any stale in-memory
     * entries left over from a hot reload or an interrupted delete
     * are purged - keeps the Library and the retriever in sync.
     */
    @PostConstruct
    public void rehydrate() {
        ensureStorageDir();
        int loaded = reconcileVectorStore();
        log.info("Research Studio rehydrated {} chunks into the vector store", loaded);
    }

    /**
     * Reconcile the in-memory vector store against the chunk table,
     * which is the authoritative source. Anything in the DB is
     * upserted; anything in the store that isn't backed by a DB row
     * is dropped. Safe to call at any time - idempotent and cheap
     * enough to run on every delete so RAG never surfaces phantom
     * citations for a document the user thought they removed.
     *
     * @return number of chunks present in the store after reconciliation.
     */
    public synchronized int reconcileVectorStore() {
        // Snapshot the store before touching the DB so we can diff.
        int before = vectorStore.size();
        // We don't have a bulk "list keys" API on the store, so we
        // rebuild from scratch - clear + re-insert. For our corpora
        // (a few hundred chunks per bundle) this is trivially cheap.
        vectorStore.clear();
        int loaded = 0;
        for (ResearchDocumentChunk row : chunkRepository.findAll()) {
            byte[] raw = row.getEmbedding();
            if (raw == null || raw.length == 0) continue;
            float[] vec;
            try {
                vec = bytesToFloats(raw);
            } catch (Exception e) {
                log.warn("Reconcile skipped chunk {}: bad embedding bytes ({})",
                        row.getId(), e.getMessage());
                continue;
            }
            vectorStore.upsert(new Chunk(
                    row.getId(),
                    row.getSourceLabel(),
                    row.getText(),
                    vec
            ));
            loaded++;
        }
        log.info("Vector store reconciled: before={} after={} (DB authoritative)",
                before, loaded);
        return loaded;
    }

    /**
     * Accept an uploaded file, persist metadata + bytes, return the
     * freshly-created document row. Processing runs asynchronously;
     * the caller sees the row transition from {@code UPLOADED} to
     * {@code PROCESSING} to {@code READY} (or {@code FAILED}) over
     * subsequent polls of the Library endpoint.
     */
    public ResearchDocument ingest(MultipartFile file, String productLabel) {
        return ingest(file, productLabel, null);
    }

    public ResearchDocument ingest(MultipartFile file, String productLabel, String bundleId) {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Upload is empty");
        }
        ensureStorageDir();

        String id = UUID.randomUUID().toString();
        String originalName = sanitizeFileName(file.getOriginalFilename());
        Path dest = Paths.get(storageDir, id + "__" + originalName);

        try {
            Files.copy(file.getInputStream(), dest, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new RuntimeException("Failed to persist upload: " + e.getMessage(), e);
        }

        ResearchDocument doc = ResearchDocument.builder()
                .id(id)
                .fileName(originalName)
                .sizeBytes(file.getSize())
                .contentType(file.getContentType())
                .storagePath(dest.toAbsolutePath().toString())
                .productLabel(productLabel)
                .bundleId(bundleId)
                .chunkCount(0)
                .status(IngestStatus.UPLOADED)
                // Provisional classification from the filename alone -
                // the async worker will refine it once the PDF is
                // extracted and the text sample is available.
                .sourceType(sourceTypeClassifier.classify(originalName, null))
                .uploadedAt(LocalDateTime.now())
                .build();
        documentRepository.save(doc);

        ingestExecutor.submit(() -> {
            try {
                processAsync(id);
            } catch (Throwable t) {
                // Belt-and-braces: if processAsync itself throws before
                // its own try/catch runs (e.g. DB not reachable), flip
                // the row to FAILED so the UI isn't stuck on UPLOADED.
                log.error("Ingest worker crashed for {}: {}", id, t.getMessage(), t);
                try {
                    documentRepository.findById(id).ifPresent(d -> {
                        d.setStatus(IngestStatus.FAILED);
                        d.setErrorMessage(truncate("Worker crashed: " + t.getMessage(), 2000));
                        documentRepository.save(d);
                    });
                } catch (Exception inner) {
                    log.error("Could not flag document {} as FAILED: {}", id, inner.getMessage());
                }
            }
        });
        return doc;
    }

    /**
     * Ingest a file already sitting on disk (e.g. dropped into a
     * bundle's watch folder by an external process). We still copy it
     * into our managed storage directory so the original location can
     * be archived or moved away; the DB row then refers to the copy.
     */
    public ResearchDocument ingestFromPath(Path sourcePath, String productLabel, String bundleId) {
        if (sourcePath == null || !Files.isRegularFile(sourcePath)) {
            throw new IllegalArgumentException("Source is not a regular file: " + sourcePath);
        }
        ensureStorageDir();

        String id = UUID.randomUUID().toString();
        String originalName = sanitizeFileName(sourcePath.getFileName().toString());
        Path dest = Paths.get(storageDir, id + "__" + originalName);
        long sizeBytes;
        String contentType = null;

        try {
            sizeBytes = Files.size(sourcePath);
            try {
                contentType = Files.probeContentType(sourcePath);
            } catch (IOException probeIgnored) {
                // best-effort; we don't need the content type for anything critical
            }
            Files.copy(sourcePath, dest, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new RuntimeException("Failed to copy watched file: " + e.getMessage(), e);
        }

        ResearchDocument doc = ResearchDocument.builder()
                .id(id)
                .fileName(originalName)
                .sizeBytes(sizeBytes)
                .contentType(contentType)
                .storagePath(dest.toAbsolutePath().toString())
                .productLabel(productLabel)
                .bundleId(bundleId)
                .chunkCount(0)
                .status(IngestStatus.UPLOADED)
                // Provisional classification from the filename alone -
                // will be refined by processAsync once the text is out.
                .sourceType(sourceTypeClassifier.classify(originalName, null))
                .uploadedAt(LocalDateTime.now())
                .build();
        documentRepository.save(doc);

        ingestExecutor.submit(() -> {
            try {
                processAsync(id);
            } catch (Throwable t) {
                log.error("Watch-ingest worker crashed for {}: {}", id, t.getMessage(), t);
                try {
                    documentRepository.findById(id).ifPresent(d -> {
                        d.setStatus(IngestStatus.FAILED);
                        d.setErrorMessage(truncate("Worker crashed: " + t.getMessage(), 2000));
                        documentRepository.save(d);
                    });
                } catch (Exception inner) {
                    log.error("Could not flag document {} as FAILED: {}", id, inner.getMessage());
                }
            }
        });
        return doc;
    }

    /**
     * Kick the async pipeline again for an existing row. Useful when a
     * document is stuck on UPLOADED (e.g. backend was restarted mid-ingest
     * or Ollama wasn't running the first time). Returns true if a worker
     * was queued.
     */
    public boolean reingest(String documentId) {
        ResearchDocument doc = documentRepository.findById(documentId).orElse(null);
        if (doc == null) {
            log.warn("Re-ingest requested for unknown document id {}", documentId);
            return false;
        }
        doc.setStatus(IngestStatus.UPLOADED);
        doc.setErrorMessage(null);
        documentRepository.save(doc);
        ingestExecutor.submit(() -> {
            try {
                processAsync(documentId);
            } catch (Throwable t) {
                log.error("Re-ingest worker crashed for {}: {}", documentId, t.getMessage(), t);
            }
        });
        return true;
    }

    /**
     * Delete a document and every trace of it: vector-store entries,
     * chunk rows, document row, and the binary on disk. Idempotent -
     * missing files or missing rows are logged and ignored.
     */
    @Transactional
    public void delete(String documentId) {
        ResearchDocument doc = documentRepository.findById(documentId).orElse(null);
        if (doc == null) {
            log.warn("Delete requested for unknown document id {}", documentId);
            return;
        }
        // Belt-and-braces: remove every source-label variant this
        // document was ever known by. Historically we only called
        // deleteBySource with the filename, so differently-cased or
        // renamed labels could leak through. We collect every distinct
        // source label the chunk table knows for this document id and
        // purge each one.
        List<ResearchDocumentChunk> chunks = chunkRepository.findByDocumentIdOrderByOrdinalAsc(documentId);
        java.util.Set<String> labels = new java.util.HashSet<>();
        if (doc.getFileName() != null) labels.add(doc.getFileName());
        for (ResearchDocumentChunk c : chunks) {
            if (c.getSourceLabel() != null) labels.add(c.getSourceLabel());
        }
        for (String label : labels) {
            vectorStore.deleteBySource(label);
        }
        chunkRepository.deleteByDocumentId(documentId);
        documentRepository.deleteById(documentId);
        try {
            Files.deleteIfExists(Paths.get(doc.getStoragePath()));
        } catch (IOException e) {
            log.warn("Could not delete file {}: {}", doc.getStoragePath(), e.getMessage());
        }
        // Final safety net: if the store still has rows that aren't
        // backed by a DB chunk (stale from a prior crash / hot reload),
        // this wipes them too. Cheap enough on our corpus size.
        reconcileVectorStore();
        log.info("Deleted research document '{}' ({} chunks, {} label(s) purged)",
                doc.getFileName(), chunks.size(), labels.size());
    }

    /**
     * Background worker. Any exception flips the row to FAILED with the
     * exception message captured, so the UI always reflects truth.
     */
    private void processAsync(String documentId) {
        ResearchDocument doc = documentRepository.findById(documentId).orElse(null);
        if (doc == null) {
            log.error("Ingest worker could not find document {}", documentId);
            return;
        }

        try {
            doc.setStatus(IngestStatus.PROCESSING);
            documentRepository.save(doc);

            File file = new File(doc.getStoragePath());
            List<Chunker.Chunk> pieces;
            Integer pageCount = null;
            String contentType = doc.getContentType() == null ? "" : doc.getContentType();
            String lowerName = doc.getFileName().toLowerCase();
            boolean isPdf = contentType.contains("pdf") || lowerName.endsWith(".pdf");

            if (isPdf) {
                List<PdfExtractor.ExtractedPage> pages = pdfExtractor.extract(file);
                pageCount = pdfExtractor.countPages(file);
                pieces = chunker.chunk(pages);
            } else {
                // Fallback: treat as UTF-8 text. Covers .md, .txt, .csv
                // and anything else the user throws at us that isn't
                // a PDF. Binary files will produce mojibake here but
                // we'll surface a FAILED state via the embed step.
                String text = Files.readString(file.toPath());
                pieces = chunker.chunkPlainText(text);
            }

            if (pieces.isEmpty()) {
                throw new IllegalStateException("Extractor produced zero chunks");
            }

            doc.setPageCount(pageCount);

            // Refine the source-type classification now that we've
            // actually got text. We only overwrite UNKNOWN or a stale
            // VENDOR_MANUAL default so that an explicit DATASHEET or
            // ACADEMIC hit from the filename isn't silently demoted by
            // boilerplate in the body text.
            if (doc.getSourceType() == null
                    || doc.getSourceType() == ResearchDocument.SourceType.UNKNOWN
                    || doc.getSourceType() == ResearchDocument.SourceType.VENDOR_MANUAL) {
                StringBuilder sample = new StringBuilder();
                for (Chunker.Chunk piece : pieces) {
                    if (sample.length() > 2048) break;
                    if (piece.text() != null) sample.append(piece.text()).append('\n');
                }
                ResearchDocument.SourceType refined =
                        sourceTypeClassifier.classify(doc.getFileName(), sample.toString());
                // Don't demote: if the filename said VENDOR_MANUAL and
                // the body classifier says UNKNOWN, keep VENDOR_MANUAL.
                if (refined != ResearchDocument.SourceType.UNKNOWN) {
                    doc.setSourceType(refined);
                }
            }

            documentRepository.save(doc);

            // Purge any previous chunks for this document - keeps
            // re-ingestion idempotent if we ever add that path.
            chunkRepository.deleteByDocumentId(documentId);
            vectorStore.deleteBySource(doc.getFileName());

            int saved = 0;
            for (Chunker.Chunk piece : pieces) {
                float[] vec;
                try {
                    vec = embeddings.embed(piece.text());
                } catch (Exception e) {
                    log.warn("Embed failed for chunk {} of {}: {}",
                            piece.ordinal(), doc.getFileName(), e.getMessage());
                    continue;
                }

                String chunkId = documentId + "::" + piece.ordinal();
                ResearchDocumentChunk row = ResearchDocumentChunk.builder()
                        .id(chunkId)
                        .documentId(documentId)
                        .ordinal(piece.ordinal())
                        .pageNumber(piece.pageNumber())
                        .text(piece.text())
                        .embedding(floatsToBytes(vec))
                        .sourceLabel(doc.getFileName())
                        .build();
                chunkRepository.save(row);

                vectorStore.upsert(new Chunk(chunkId, doc.getFileName(), piece.text(), vec));
                saved++;
            }

            if (saved == 0) {
                throw new IllegalStateException("All embeddings failed - is Ollama running?");
            }

            doc.setChunkCount(saved);
            doc.setStatus(IngestStatus.READY);
            doc.setIngestedAt(LocalDateTime.now());
            doc.setErrorMessage(null);
            documentRepository.save(doc);
            log.info("Ingest complete for '{}': {} chunks indexed", doc.getFileName(), saved);

        } catch (Exception e) {
            log.error("Ingest failed for document {}: {}", documentId, e.getMessage(), e);
            doc.setStatus(IngestStatus.FAILED);
            doc.setErrorMessage(truncate(e.getMessage(), 2000));
            documentRepository.save(doc);
        }
    }

    /** Make sure the upload directory exists on the first write. */
    private void ensureStorageDir() {
        try {
            Files.createDirectories(Paths.get(storageDir));
        } catch (IOException e) {
            throw new RuntimeException("Cannot create research storage dir: " + storageDir, e);
        }
    }

    /**
     * Strip path separators so a malicious file name can't escape the
     * storage directory, and fall back to a default if the client
     * forgot to send one.
     */
    private static String sanitizeFileName(String raw) {
        if (raw == null || raw.isBlank()) return "document.bin";
        String cleaned = raw.replace('\\', '/');
        int slash = cleaned.lastIndexOf('/');
        if (slash >= 0) cleaned = cleaned.substring(slash + 1);
        cleaned = cleaned.replaceAll("[^A-Za-z0-9._-]", "_");
        return cleaned.length() > 200 ? cleaned.substring(cleaned.length() - 200) : cleaned;
    }

    private static String truncate(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max);
    }

    /** Serialise a float[] as little-endian bytes for BYTEA storage. */
    public static byte[] floatsToBytes(float[] floats) {
        ByteBuffer buf = ByteBuffer.allocate(floats.length * 4).order(ByteOrder.LITTLE_ENDIAN);
        for (float f : floats) buf.putFloat(f);
        return buf.array();
    }

    /** Inverse of {@link #floatsToBytes}. */
    public static float[] bytesToFloats(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        float[] out = new float[bytes.length / 4];
        for (int i = 0; i < out.length; i++) out[i] = buf.getFloat();
        return out;
    }
}
